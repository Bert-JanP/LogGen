#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Resources, Az.Automation, Az.KeyVault, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Removes the Key Vault audit logging lab created by Deploy-KeyVaultAuditLab.ps1.

.DESCRIPTION
    Removes the subscription-scope role assignment of the Automation managed identity, deletes the resource group,
    purges the soft-deleted lab vaults and deletes the lab app registrations.

.EXAMPLE
    ./Remove-KeyVaultAuditLab.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -ResourceGroupName rg-kv-auditlab -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [ValidatePattern('^[a-z][a-z0-9]{1,12}$')][string]$NamePrefix = 'kvaudit',
    [switch]$KeepAppRegistrations
)

$ErrorActionPreference = 'Stop'
$context = try { Set-AzContext -Subscription $SubscriptionId.Guid -ErrorAction Stop } catch { $null }
$probe = if ($context) { try { Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId)?api-version=2022-12-01" -ErrorAction Stop } catch { $null } }
if ($probe.StatusCode -ne 200) {
    Write-Host 'Signing in to Azure (Az PowerShell)...' -ForegroundColor Yellow
    $null = Connect-AzAccount -Subscription $SubscriptionId.Guid -ErrorAction Stop
    $context = Set-AzContext -Subscription $SubscriptionId.Guid -ErrorAction Stop
}
$tenantId = $context.Tenant.Id
$subscriptionScope = "/subscriptions/$SubscriptionId"
$automationAccountName = "$NamePrefix-kvlab-aa"
$hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes("$SubscriptionId/$ResourceGroupName".ToLowerInvariant()))
$suffix = -join ($hash[0..2] | ForEach-Object { $_.ToString('x2') })
$vaultNamePattern = "^$NamePrefix-$suffix-\d{2}$"

$resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
$labVaults = @()
if ($resourceGroup) {
    $labVaults = @(Get-AzKeyVault -ResourceGroupName $ResourceGroupName | Where-Object { $_.Tags.AuditLab -eq 'true' -and $_.VaultName -match $vaultNamePattern })

    $automationAccount = try { Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $automationAccountName } catch { $null }
    $principalId = $automationAccount.Identity.PrincipalId
    if ($principalId) {
        $filter = [uri]::EscapeDataString("principalId eq '$principalId'")
        $assignments = Invoke-AzRestMethod -Method GET -Path "$subscriptionScope/providers/Microsoft.Authorization/roleAssignments?`$filter=$filter&api-version=2022-04-01"
        ($assignments.Content | ConvertFrom-Json).value |
            Where-Object { $_.properties.scope -eq $subscriptionScope } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess("$($_.properties.roleDefinitionId) on $subscriptionScope", 'Remove role assignment')) {
                    $null = Invoke-AzRestMethod -Method DELETE -Path "$($_.id)?api-version=2022-04-01"
                }
            }
    }

    if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Delete resource group')) {
        Write-Host "Deleting resource group $ResourceGroupName"
        $null = Remove-AzResourceGroup -Name $ResourceGroupName -Force
    }
}
else {
    Write-Warning "Resource group $ResourceGroupName not found."
}

$deletedVaults = @(Get-AzKeyVault -InRemovedState | Where-Object { $_.VaultName -match $vaultNamePattern })
foreach ($vault in $labVaults | Where-Object { $deletedVaults.VaultName -notcontains $_.VaultName }) {
    # Vaults deleted with the resource group can take a moment to appear in the removed state.
    $deleted = $null
    for ($attempt = 1; $attempt -le 12 -and -not $deleted; $attempt++) {
        $deleted = Get-AzKeyVault -VaultName $vault.VaultName -Location $vault.Location -InRemovedState -ErrorAction SilentlyContinue
        if (-not $deleted -and -not $WhatIfPreference) { Start-Sleep -Seconds 10 }
        if ($WhatIfPreference) { break }
    }
    if ($deleted) { $deletedVaults += $deleted }
}

foreach ($vault in $deletedVaults) {
    if ($PSCmdlet.ShouldProcess($vault.VaultName, 'Purge soft-deleted key vault')) {
        Write-Host "Purging vault $($vault.VaultName)"
        Remove-AzKeyVault -VaultName $vault.VaultName -Location $vault.Location -InRemovedState -Force
    }
}

if (-not $KeepAppRegistrations) {
    $graph = Get-MgContext
    if (-not $graph -or $graph.TenantId -ne $tenantId -or ($graph.AuthType -eq 'Delegated' -and $graph.Scopes -notcontains 'Application.ReadWrite.All')) {
        Write-Host "Signing in to Microsoft Graph (tenant $tenantId)..." -ForegroundColor Yellow
        Connect-MgGraph -TenantId $tenantId -Scopes 'Application.ReadWrite.All' -NoWelcome -ErrorAction Stop
    }
    $filter = [uri]::EscapeDataString("startswith(displayName,'$NamePrefix-')")
    $apps = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter&`$select=id,displayName" -OutputType PSObject).value
    $apps |
        Where-Object displayName -Match "^$NamePrefix-(app|certops|reader)-\d{2}$" |
        ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.displayName, 'Delete app registration')) {
                Write-Host "Deleting app registration $($_.displayName)"
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/applications/$($_.id)"
            }
        }
}

Write-Host 'Cleanup complete.' -ForegroundColor Green
