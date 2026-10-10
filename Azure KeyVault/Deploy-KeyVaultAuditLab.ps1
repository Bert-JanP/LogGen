#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Resources, Az.Automation, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Deploys a Key Vault audit logging lab: n key vaults, app identities and an Automation runbook that simulates activity.

.DESCRIPTION
    Idempotent. Creates (or updates) in the given subscription/resource group:
    - n key vaults (mixed RBAC / access policy model, soft delete on, purge protection off)
    - Entra app registrations + service principals acting as "applications" (secrets stored as Automation credentials)
    - An Automation Account with system-assigned managed identity, the simulation runbook and a recurring schedule
    Diagnostic settings are NOT created; log collection is expected to be enforced by Azure Policy.

    Authentication: Azure resources use the Az PowerShell session, Entra ID objects use the Microsoft Graph
    PowerShell session (scope Application.ReadWrite.All). Both are validated up front and you are prompted to sign
    in to the subscription's tenant when a session is missing or unusable.

.EXAMPLE
    ./Deploy-KeyVaultAuditLab.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -ResourceGroupName rg-kv-auditlab -Location westeurope -VaultCount 3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$Location,
    [guid]$TenantId,
    [ValidateRange(1, 50)][int]$VaultCount = 3,
    [ValidatePattern('^[a-z][a-z0-9]{1,12}$')][string]$NamePrefix = 'kvaudit',
    [ValidateRange(0, 20)][int]$AppIdentityCount = 3,
    [ValidateRange(0.0, 1.0)][double]$RbacVaultRatio = 0.5,
    [ValidateRange(1, 24)][int]$ScheduleIntervalHours = 1,
    [ValidateRange(1, 730)][int]$AppSecretValidityDays = 90,
    [switch]$RotateAppSecrets
)

$ErrorActionPreference = 'Stop'
$ArmApiVersion = '2023-07-01'
$RunbookPath = Join-Path $PSScriptRoot 'Runbooks/Invoke-KeyVaultActivitySimulation.ps1'
$RunbookName = 'Invoke-KeyVaultActivitySimulation'
$ScheduleName = 'KvLab-Recurring'
$Location = $Location.ToLowerInvariant().Replace(' ', '')

$AccessPolicyPermissions = @{
    Admin   = @{
        keys         = @('get', 'list', 'update', 'create', 'import', 'delete', 'recover', 'backup', 'restore', 'decrypt', 'encrypt', 'unwrapKey', 'wrapKey', 'verify', 'sign', 'purge', 'rotate', 'getrotationpolicy', 'setrotationpolicy')
        secrets      = @('get', 'list', 'set', 'delete', 'recover', 'backup', 'restore', 'purge')
        certificates = @('get', 'list', 'update', 'create', 'import', 'delete', 'recover', 'backup', 'restore', 'managecontacts', 'manageissuers', 'getissuers', 'listissuers', 'setissuers', 'deleteissuers', 'purge')
    }
    App     = @{
        keys         = @('get', 'list', 'sign', 'verify', 'wrapKey', 'unwrapKey', 'encrypt', 'decrypt')
        secrets      = @('get', 'list')
        certificates = @()
    }
    CertOps = @{
        keys         = @()
        secrets      = @()
        certificates = @('get', 'list', 'update', 'create', 'import', 'delete', 'recover', 'backup', 'restore', 'managecontacts', 'getissuers', 'listissuers')
    }
    Reader  = @{
        keys         = @('get', 'list')
        secrets      = @('list')
        certificates = @('get', 'list')
    }
}

$RbacRoles = @{
    App     = @('Key Vault Crypto User', 'Key Vault Secrets User')
    CertOps = @('Key Vault Certificates Officer')
    Reader  = @('Key Vault Reader')
}

function Invoke-ArmRequest {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [int[]]$AllowedStatus = @()
    )
    $params = @{ Method = $Method; Path = $Path }
    if ($null -ne $Body) { $params.Payload = $Body | ConvertTo-Json -Depth 20 }
    $response = Invoke-AzRestMethod @params
    if ($response.StatusCode -ge 400 -and $AllowedStatus -notcontains $response.StatusCode) {
        throw "$Method $Path failed with HTTP $($response.StatusCode): $($response.Content)"
    }
    $response
}

function Invoke-Graph {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body
    )
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
        $params.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @params
}

function Get-GraphSingle {
    param([string]$Collection, [string]$Filter)
    $result = Invoke-Graph -Method GET -Uri "$($Collection)?`$filter=$([uri]::EscapeDataString($Filter))"
    @($result.value)[0]
}

function Connect-LabAzure {
    $context = $null
    try { $context = Set-AzContext -Subscription $SubscriptionId.Guid -ErrorAction Stop } catch { }
    if ($context -and (-not $TenantId -or $context.Tenant.Id -eq $TenantId.Guid)) {
        $probe = try { Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId)?api-version=2022-12-01" -ErrorAction Stop } catch { $null }
        if ($probe.StatusCode -eq 200) { return $context }
    }

    Write-Host 'Signing in to Azure (Az PowerShell)...' -ForegroundColor Yellow
    $connect = @{ Subscription = $SubscriptionId.Guid; ErrorAction = 'Stop' }
    if ($TenantId) { $connect.Tenant = $TenantId.Guid }
    elseif ($context) { $connect.Tenant = $context.Tenant.Id }
    $null = Connect-AzAccount @connect
    $context = Set-AzContext -Subscription $SubscriptionId.Guid -ErrorAction Stop
    $probe = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId)?api-version=2022-12-01" -ErrorAction Stop
    if ($probe.StatusCode -ne 200) { throw "Cannot read subscription $SubscriptionId (HTTP $($probe.StatusCode)): $($probe.Content)" }
    $context
}

function Connect-LabGraph {
    param([string]$Tenant)
    $requiredScope = 'Application.ReadWrite.All'
    $graph = Get-MgContext
    $usable = $graph -and $graph.TenantId -eq $Tenant -and
        ($graph.AuthType -ne 'Delegated' -or $graph.Scopes -contains $requiredScope)
    if ($usable) {
        try { $null = Invoke-Graph -Method GET -Uri 'organization?$select=id' } catch { $usable = $false }
    }
    if (-not $usable) {
        Write-Host "Signing in to Microsoft Graph (tenant $Tenant, scope $requiredScope)..." -ForegroundColor Yellow
        Connect-MgGraph -TenantId $Tenant -Scopes $requiredScope -NoWelcome -ErrorAction Stop
        $graph = Get-MgContext
    }
    $graph
}

function Set-LabRoleAssignment {
    param(
        [string]$PrincipalId,
        [ValidateSet('User', 'ServicePrincipal')][string]$PrincipalType,
        [string]$RoleName,
        [string]$Scope
    )
    if (-not $script:RoleDefinitionIds.ContainsKey($RoleName)) {
        $definition = Get-AzRoleDefinition -Name $RoleName -ErrorAction Stop
        $script:RoleDefinitionIds[$RoleName] = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($definition.Id)"
    }
    $roleDefinitionId = $script:RoleDefinitionIds[$RoleName]

    # Deterministic name keeps re-runs idempotent.
    $nameHash = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes("$Scope|$PrincipalId|$roleDefinitionId".ToLowerInvariant()))
    $path = "$Scope/providers/Microsoft.Authorization/roleAssignments/$([guid]::new($nameHash))?api-version=2022-04-01"
    $body = @{ properties = @{ roleDefinitionId = $roleDefinitionId; principalId = $PrincipalId; principalType = $PrincipalType } }

    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $response = Invoke-AzRestMethod -Method PUT -Path $path -Payload ($body | ConvertTo-Json -Depth 5)
        if ($response.StatusCode -in 200, 201) { Write-Host "  Assigned '$RoleName' to $PrincipalId on $Scope"; return }
        if ($response.StatusCode -eq 409) { return }
        # New principals take a while to replicate in Entra ID.
        if ($response.Content -match 'PrincipalNotFound' -and $attempt -lt 12) { Start-Sleep -Seconds 10; continue }
        throw "Role assignment '$RoleName' for $PrincipalId on $Scope failed (HTTP $($response.StatusCode)): $($response.Content)"
    }
}

function Set-LabAutomationVariable {
    param([string]$AutomationAccountName, [string]$Name, [string]$Value)
    $common = @{ ResourceGroupName = $ResourceGroupName; AutomationAccountName = $AutomationAccountName; Name = $Name }
    $existing = try { Get-AzAutomationVariable @common } catch { $null }
    if ($existing) { $null = Set-AzAutomationVariable @common -Encrypted $false -Value $Value }
    else { $null = New-AzAutomationVariable @common -Encrypted $false -Value $Value }
}

function New-LabAccessPolicy {
    param([string]$TenantId, [string]$ObjectId, [hashtable]$Permissions)
    @{ tenantId = $TenantId; objectId = $ObjectId; permissions = $Permissions }
}

#region Context
$script:RoleDefinitionIds = @{}
$context = Connect-LabAzure
$tenantId = $context.Tenant.Id
$subscriptionScope = "/subscriptions/$SubscriptionId"
Write-Host "Azure: $($context.Account.Id) on subscription $SubscriptionId (tenant $tenantId)"

$graph = Connect-LabGraph -Tenant $tenantId
if ($graph.AuthType -eq 'Delegated') {
    $currentPrincipalId = (Invoke-Graph -Method GET -Uri 'me?$select=id').id
    $currentPrincipalType = 'User'
}
else {
    $currentPrincipalId = (Get-GraphSingle -Collection 'servicePrincipals' -Filter "appId eq '$($graph.ClientId)'").id
    $currentPrincipalType = 'ServicePrincipal'
}
Write-Host "Graph: $($graph.Account ?? $graph.ClientId) ($currentPrincipalId)"
if ($graph.Account -and $context.Account.Type -eq 'User' -and $graph.Account -ne $context.Account.Id) {
    Write-Warning "Az ($($context.Account.Id)) and Graph ($($graph.Account)) are signed in as different accounts; lab admin rights go to the Graph account."
}

$hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes("$SubscriptionId/$ResourceGroupName".ToLowerInvariant()))
$suffix = -join ($hash[0..2] | ForEach-Object { $_.ToString('x2') })
$automationAccountName = "$NamePrefix-kvlab-aa"
#endregion

#region Resource group
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating resource group $ResourceGroupName"
    $null = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag @{ AuditLab = 'true' }
}
$resourceGroupScope = "$subscriptionScope/resourceGroups/$ResourceGroupName"
#endregion

#region Automation account
$automationAccount = try { Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $automationAccountName } catch { $null }
if (-not $automationAccount) {
    Write-Host "Creating Automation Account $automationAccountName"
    $automationAccount = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $automationAccountName -Location $Location -AssignSystemIdentity
}
elseif (-not $automationAccount.Identity.PrincipalId) {
    $automationAccount = Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $automationAccountName -AssignSystemIdentity
}
$automationPrincipalId = $automationAccount.Identity.PrincipalId
#endregion

#region App identities
$profiles = @('App', 'CertOps', 'Reader')
$identities = [System.Collections.Generic.List[object]]::new()
for ($i = 1; $i -le $AppIdentityCount; $i++) {
    $identityProfile = $profiles[($i - 1) % $profiles.Count]
    $displayName = '{0}-{1}-{2:D2}' -f $NamePrefix, $identityProfile.ToLowerInvariant(), $i
    Write-Host "Ensuring app identity $displayName ($identityProfile)"

    $app = Get-GraphSingle -Collection 'applications' -Filter "displayName eq '$displayName'"
    if (-not $app) {
        $app = Invoke-Graph -Method POST -Uri 'applications' -Body @{ displayName = $displayName; signInAudience = 'AzureADMyOrg' }
    }
    $sp = Get-GraphSingle -Collection 'servicePrincipals' -Filter "appId eq '$($app.appId)'"
    for ($attempt = 1; -not $sp; $attempt++) {
        try { $sp = Invoke-Graph -Method POST -Uri 'servicePrincipals' -Body @{ appId = $app.appId } }
        catch {
            # A just-created application may not be replicated yet.
            if ($attempt -ge 6) { throw }
            Start-Sleep -Seconds 10
        }
    }

    $credentialName = "KvLab-$displayName"
    $credentialParams = @{ ResourceGroupName = $ResourceGroupName; AutomationAccountName = $automationAccountName; Name = $credentialName }
    $existingCredential = try { Get-AzAutomationCredential @credentialParams } catch { $null }
    if (-not $existingCredential -or $RotateAppSecrets) {
        $passwordBody = @{ passwordCredential = @{ displayName = 'KvAuditLab runbook'; endDateTime = [datetime]::UtcNow.AddDays($AppSecretValidityDays).ToString('o') } }
        $secret = Invoke-Graph -Method POST -Uri "applications/$($app.id)/addPassword" -Body $passwordBody
        $credential = [pscredential]::new($app.appId, (ConvertTo-SecureString -String $secret.secretText -AsPlainText -Force))
        if ($existingCredential) { $null = Set-AzAutomationCredential @credentialParams -Value $credential }
        else { $null = New-AzAutomationCredential @credentialParams -Value $credential }
    }

    $identities.Add([pscustomobject]@{
            name           = $displayName
            profile        = $identityProfile
            appId          = $app.appId
            objectId       = $sp.id
            credentialName = $credentialName
        })
}
#endregion

#region Key vaults
$rbacVaultCount = [math]::Ceiling($VaultCount * $RbacVaultRatio)
$vaults = [System.Collections.Generic.List[object]]::new()
for ($i = 1; $i -le $VaultCount; $i++) {
    $vaultName = '{0}-{1}-{2:D2}' -f $NamePrefix, $suffix, $i
    $permissionModel = if ($i -le $rbacVaultCount) { 'RBAC' } else { 'AccessPolicy' }
    # Only one vault is ever deleted/recovered by the runbook.
    $labRole = if ($VaultCount -ge 2 -and $i -eq $VaultCount) { 'Churn' } else { 'Standard' }
    $vaultPath = "$resourceGroupScope/providers/Microsoft.KeyVault/vaults/$($vaultName)?api-version=$ArmApiVersion"

    $existing = Invoke-ArmRequest -Method GET -Path $vaultPath -AllowedStatus 404
    if ($existing.StatusCode -eq 404) {
        $deletedPath = "$subscriptionScope/providers/Microsoft.KeyVault/locations/$Location/deletedVaults/$($vaultName)?api-version=$ArmApiVersion"
        $deleted = Invoke-ArmRequest -Method GET -Path $deletedPath -AllowedStatus 404
        if ($deleted.StatusCode -eq 200) {
            Write-Host "Recovering soft-deleted vault $vaultName"
            $body = @{ location = $Location; properties = @{ tenantId = $tenantId; sku = @{ family = 'A'; name = 'standard' }; createMode = 'recover' } }
        }
        else {
            Write-Host "Creating vault $vaultName ($permissionModel, $labRole)"
            $body = @{
                location   = $Location
                tags       = @{ AuditLab = 'true'; PermissionModel = $permissionModel; LabRole = $labRole }
                properties = @{
                    tenantId                  = $tenantId
                    sku                       = @{ family = 'A'; name = 'standard' }
                    enableRbacAuthorization   = ($permissionModel -eq 'RBAC')
                    enableSoftDelete          = $true
                    softDeleteRetentionInDays = 7
                    publicNetworkAccess       = 'Enabled'
                    accessPolicies            = @()
                }
            }
        }
        $null = Invoke-ArmRequest -Method PUT -Path $vaultPath -Body $body
        $existing = Invoke-ArmRequest -Method GET -Path $vaultPath
    }
    else {
        Write-Host "Vault $vaultName already exists"
    }
    $vault = $existing.Content | ConvertFrom-Json
    $permissionModel = if ($vault.properties.enableRbacAuthorization) { 'RBAC' } else { 'AccessPolicy' }

    if ($permissionModel -eq 'AccessPolicy') {
        $policies = @(
            New-LabAccessPolicy -TenantId $tenantId -ObjectId $automationPrincipalId -Permissions $AccessPolicyPermissions.Admin
            New-LabAccessPolicy -TenantId $tenantId -ObjectId $currentPrincipalId -Permissions $AccessPolicyPermissions.Admin
            foreach ($identity in $identities) {
                New-LabAccessPolicy -TenantId $tenantId -ObjectId $identity.objectId -Permissions $AccessPolicyPermissions[$identity.profile]
            }
        )
        $policyPath = "$resourceGroupScope/providers/Microsoft.KeyVault/vaults/$vaultName/accessPolicies/add?api-version=$ArmApiVersion"
        $null = Invoke-ArmRequest -Method PUT -Path $policyPath -Body @{ properties = @{ accessPolicies = $policies } }
    }

    $vaults.Add([pscustomobject]@{
            name            = $vaultName
            uri             = $vault.properties.vaultUri.TrimEnd('/')
            location        = $vault.location
            permissionModel = $permissionModel
            role            = $labRole
        })
}
#endregion

#region Role assignments
Write-Host 'Ensuring role assignments'
Set-LabRoleAssignment -PrincipalId $automationPrincipalId -PrincipalType ServicePrincipal -RoleName 'Key Vault Administrator' -Scope $resourceGroupScope
# Subscription scope is required to read and recover deleted vaults.
Set-LabRoleAssignment -PrincipalId $automationPrincipalId -PrincipalType ServicePrincipal -RoleName 'Key Vault Contributor' -Scope $subscriptionScope
Set-LabRoleAssignment -PrincipalId $currentPrincipalId -PrincipalType $currentPrincipalType -RoleName 'Key Vault Administrator' -Scope $resourceGroupScope
foreach ($identity in $identities) {
    foreach ($role in $RbacRoles[$identity.profile]) {
        Set-LabRoleAssignment -PrincipalId $identity.objectId -PrincipalType ServicePrincipal -RoleName $role -Scope $resourceGroupScope
    }
}
#endregion

#region Automation configuration
Write-Host 'Writing Automation variables'
Set-LabAutomationVariable -AutomationAccountName $automationAccountName -Name 'KvLab_SubscriptionId' -Value $SubscriptionId.Guid
Set-LabAutomationVariable -AutomationAccountName $automationAccountName -Name 'KvLab_ResourceGroupName' -Value $ResourceGroupName
Set-LabAutomationVariable -AutomationAccountName $automationAccountName -Name 'KvLab_TenantId' -Value $tenantId
Set-LabAutomationVariable -AutomationAccountName $automationAccountName -Name 'KvLab_Vaults' -Value (ConvertTo-Json -InputObject @($vaults) -Depth 5 -Compress)
Set-LabAutomationVariable -AutomationAccountName $automationAccountName -Name 'KvLab_Identities' -Value (ConvertTo-Json -InputObject @($identities) -Depth 5 -Compress)

Write-Host "Importing runbook $RunbookName"
$null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $automationAccountName `
    -Name $RunbookName -Path $RunbookPath -Type PowerShell72 -Published -Force

$scheduleParams = @{ ResourceGroupName = $ResourceGroupName; AutomationAccountName = $automationAccountName }
$schedule = try { Get-AzAutomationSchedule @scheduleParams -Name $ScheduleName } catch { $null }
if (-not $schedule) {
    Write-Host "Creating schedule $ScheduleName (every $ScheduleIntervalHours hour(s))"
    $null = New-AzAutomationSchedule @scheduleParams -Name $ScheduleName -StartTime (Get-Date).AddMinutes(15) -HourInterval $ScheduleIntervalHours -TimeZone 'Etc/UTC'
}
$link = Get-AzAutomationScheduledRunbook @scheduleParams -RunbookName $RunbookName -ErrorAction SilentlyContinue |
    Where-Object ScheduleName -EQ $ScheduleName
if (-not $link) {
    # Leave headroom so consecutive jobs do not overlap.
    $duration = [math]::Min(170, [math]::Max(10, $ScheduleIntervalHours * 60 - 10))
    $null = Register-AzAutomationScheduledRunbook @scheduleParams -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters @{ DurationMinutes = $duration }
}
#endregion

Write-Host ''
Write-Host 'Deployment complete.' -ForegroundColor Green
$vaults | Format-Table name, permissionModel, role, uri -AutoSize
$identities | Format-Table name, profile, appId -AutoSize
Write-Host "Automation Account: $automationAccountName (managed identity $automationPrincipalId)"
Write-Host "Start a test run: Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $automationAccountName -Name $RunbookName -Parameters @{ DurationMinutes = 10 }"
