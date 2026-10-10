<#
.SYNOPSIS
    Simulates realistic Azure Key Vault activity so AuditEvent logging can be validated.

.DESCRIPTION
    Azure Automation runbook (PowerShell 7.2+ runtime). Configuration is read from the Automation variables and
    credentials created by Deploy-KeyVaultAuditLab.ps1. All calls are made with REST so every request can be
    tagged (User-Agent "KvAuditLab/1.0 (<caller>)" and x-ms-client-request-id) and correlated with the logs.

    Callers:
    - automation-mi          : Automation Account managed identity (admin / write / lifecycle operations)
    - <prefix>-app-NN        : application identity (secret reads, crypto operations)
    - <prefix>-certops-NN    : certificate operator (certificate reads and updates)
    - <prefix>-reader-NN     : metadata reader (list operations, occasional denied secret read)
#>
param(
    [ValidateRange(5, 170)][int]$DurationMinutes = 50,
    [ValidateRange(0, 600)][int]$MinDelaySeconds = 5,
    [ValidateRange(1, 1800)][int]$MaxDelaySeconds = 60,
    [ValidateRange(0.0, 1.0)][double]$DestructiveScenarioProbability = 0.05,
    [ValidateRange(0.0, 1.0)][double]$ExpiryScenarioProbability = 0.2,
    [ValidateRange(0.0, 1.0)][double]$VaultChurnProbability = 0.1
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Formats.Asn1

$KvApiVersion = '7.5'
$ArmApiVersion = '2023-07-01'
$ManagedIdentityCaller = 'automation-mi'
$UserAgent = 'KvAuditLab/1.0'

$script:Tokens = @{}
$script:Activity = [System.Collections.Generic.List[object]]::new()
$script:UnavailableVaults = [System.Collections.Generic.HashSet[string]]::new()
$script:LabCa = $null

#region Configuration
if (-not $env:IDENTITY_ENDPOINT -or -not (Get-Command -Name Get-AutomationVariable -ErrorAction SilentlyContinue)) {
    throw 'This runbook must run in Azure Automation with a system-assigned managed identity.'
}

$SubscriptionId = Get-AutomationVariable -Name 'KvLab_SubscriptionId'
$ResourceGroupName = Get-AutomationVariable -Name 'KvLab_ResourceGroupName'
$TenantId = Get-AutomationVariable -Name 'KvLab_TenantId'
$Vaults = @(Get-AutomationVariable -Name 'KvLab_Vaults' | ConvertFrom-Json)
$Identities = @{}
foreach ($entry in @(Get-AutomationVariable -Name 'KvLab_Identities' | ConvertFrom-Json)) {
    if (-not $entry) { continue }
    $credential = Get-AutomationPSCredential -Name $entry.credentialName
    $Identities[$entry.name] = [pscustomobject]@{
        Name       = $entry.name
        Role       = $entry.profile
        ObjectId   = $entry.objectId
        Credential = $credential
    }
}

$BaselineKeys = @(
    @{ Name = 'app-encryption-key'; Body = @{ kty = 'RSA'; key_size = 2048; key_ops = @('encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'sign', 'verify') } }
    @{ Name = 'app-signing-key'; Body = @{ kty = 'RSA'; key_size = 3072; key_ops = @('sign', 'verify') } }
    @{ Name = 'app-ec-key'; Body = @{ kty = 'EC'; crv = 'P-256'; key_ops = @('sign', 'verify') } }
    @{ Name = 'rotating-key'; Body = @{ kty = 'RSA'; key_size = 2048; key_ops = @('encrypt', 'decrypt', 'wrapKey', 'unwrapKey') }; Rotation = $true }
)
$BaselineSecrets = @('db-connection-string', 'api-key', 'storage-account-key', 'service-password')
$BaselineCertificates = @(
    @{ Name = 'web-tls'; Subject = 'CN=web.contoso.example'; ValidityMonths = 12; LifetimePercentage = 80 }
    # Short validity so the service performs CertificateRenew/Enroll within days.
    @{ Name = 'auto-renew-tls'; Subject = 'CN=renew.contoso.example'; ValidityMonths = 1; LifetimePercentage = 10 }
)
$LabIssuerName = 'lab-digicert'
#endregion

#region Helpers
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-RandomBytes {
    param([int]$Count = 32)
    [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($Count)
}

function Get-UnixTime {
    param([datetime]$Date)
    [DateTimeOffset]::new($Date.ToUniversalTime()).ToUnixTimeSeconds()
}

function Get-AccessToken {
    param([string]$Caller, [ValidateSet('Vault', 'Arm')][string]$Audience)
    $resource = if ($Audience -eq 'Vault') { 'https://vault.azure.net' } else { 'https://management.azure.com' }
    $cacheKey = "$Caller|$Audience"
    $cached = $script:Tokens[$cacheKey]
    if ($cached -and $cached.ExpiresOn -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { return $cached.Token }

    if ($Caller -eq $ManagedIdentityCaller) {
        $response = Invoke-RestMethod -Method Get -Uri "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString("$resource/"))" `
            -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; Metadata = 'True' }
        $expiresOnRaw = "$($response.expires_on)"
        $expiresOn = if ($expiresOnRaw -match '^\d+$') { [DateTimeOffset]::FromUnixTimeSeconds([long]$expiresOnRaw) }
        else { [DateTimeOffset]::Parse($expiresOnRaw, [cultureinfo]::InvariantCulture) }
    }
    else {
        $identity = $Identities[$Caller]
        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $identity.Credential.UserName
            client_secret = $identity.Credential.GetNetworkCredential().Password
            scope         = "$resource/.default"
        }
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Body $body -ContentType 'application/x-www-form-urlencoded'
        $expiresOn = [DateTimeOffset]::UtcNow.AddSeconds([int]$response.expires_in)
    }

    $script:Tokens[$cacheKey] = @{ Token = $response.access_token; ExpiresOn = $expiresOn }
    $response.access_token
}

function Invoke-KvRequest {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body,
        [string]$Caller = $ManagedIdentityCaller,
        [ValidateSet('Vault', 'Arm')][string]$Audience = 'Vault',
        [Parameter(Mandatory)][string]$Operation,
        [string]$VaultName,
        [int[]]$AllowedStatus = @(),
        [switch]$Anonymous
    )
    if ($Uri -notmatch 'api-version=') {
        $apiVersion = if ($Audience -eq 'Vault') { $KvApiVersion } else { $ArmApiVersion }
        $Uri += $(if ($Uri.Contains('?')) { '&' } else { '?' }) + "api-version=$apiVersion"
    }
    $requestId = [guid]::NewGuid().Guid
    $headers = @{ 'x-ms-client-request-id' = $requestId }
    $request = @{
        Method             = $Method
        Uri                = $Uri
        Headers            = $headers
        UserAgent          = "$UserAgent ($Caller)"
        ContentType        = 'application/json'
        SkipHttpErrorCheck = $true
    }
    if ($null -ne $Body) { $request.Body = $Body | ConvertTo-Json -Depth 20 -Compress }

    for ($attempt = 1; ; $attempt++) {
        if (-not $Anonymous) { $headers.Authorization = "Bearer $(Get-AccessToken -Caller $Caller -Audience $Audience)" }
        $response = Invoke-WebRequest @request
        $status = [int]$response.StatusCode
        if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 5) {
            $retryAfter = 0
            $retryHeader = if ($response.Headers.ContainsKey('Retry-After')) { $response.Headers['Retry-After'] | Select-Object -First 1 }
            if (-not [int]::TryParse("$retryHeader", [ref]$retryAfter)) {
                $retryAfter = [math]::Pow(2, $attempt)
            }
            Start-Sleep -Seconds $retryAfter
            continue
        }
        break
    }

    $data = $null
    if ($response.Content) {
        try { $data = $response.Content | ConvertFrom-Json -Depth 50 } catch { $data = $response.Content }
    }
    $script:Activity.Add([pscustomobject]@{
            Time      = [DateTime]::UtcNow
            Vault     = $VaultName
            Operation = $Operation
            Caller    = $Caller
            Status    = $status
            RequestId = $requestId
        })

    if ($status -ge 400 -and $AllowedStatus -notcontains $status) {
        $detail = if ($data.error) { "$($data.error.code): $($data.error.message)" } else { "$($response.Content)" }
        throw "$Operation on '$VaultName' as '$Caller' failed with HTTP $status. $detail"
    }
    [pscustomobject]@{ StatusCode = $status; Data = $data }
}

function Invoke-Kv {
    param(
        [Parameter(Mandatory, Position = 0)][object]$Vault,
        [Parameter(Mandatory, Position = 1)][string]$Method,
        [Parameter(Mandatory, Position = 2)][string]$Path,
        [object]$Body,
        [Parameter(Mandatory)][string]$Operation,
        [string]$Caller = $ManagedIdentityCaller,
        [int[]]$AllowedStatus = @(),
        [switch]$Anonymous
    )
    Invoke-KvRequest -Method $Method -Uri "$($Vault.uri)/$Path" -Body $Body -Caller $Caller -Operation $Operation `
        -VaultName $Vault.name -AllowedStatus $AllowedStatus -Anonymous:$Anonymous
}

function Invoke-Arm {
    param(
        [Parameter(Mandatory, Position = 0)][object]$Vault,
        [Parameter(Mandatory, Position = 1)][string]$Method,
        [Parameter(Position = 2)][string]$Path = '',
        [object]$Body,
        [Parameter(Mandatory)][string]$Operation,
        [int[]]$AllowedStatus = @()
    )
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$($Vault.name)$Path"
    Invoke-KvRequest -Method $Method -Uri $uri -Body $Body -Audience Arm -Operation $Operation -VaultName $Vault.name -AllowedStatus $AllowedStatus
}

function Get-KvCollection {
    param([object]$Vault, [string]$Path, [string]$Operation, [string]$Caller = $ManagedIdentityCaller)
    $items = [System.Collections.Generic.List[object]]::new()
    $uri = "$($Vault.uri)/$Path"
    while ($uri) {
        $page = Invoke-KvRequest -Method GET -Uri $uri -Caller $Caller -Operation $Operation -VaultName $Vault.name
        foreach ($item in @($page.Data.value)) { if ($item) { $items.Add($item) } }
        $uri = $page.Data.nextLink
    }
    , $items
}

function Get-ItemName {
    param([object]$Item)
    $id = if ($Item.kid) { $Item.kid } else { $Item.id }
    $id.Split('/')[4]
}

function Wait-Until {
    param([scriptblock]$Condition, [int]$TimeoutSeconds = 120, [int]$IntervalSeconds = 5, [string]$Description)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return }
        Start-Sleep -Seconds $IntervalSeconds
    }
    throw "Timed out after $TimeoutSeconds seconds waiting for $Description."
}

function Get-Caller {
    param([string]$IdentityRole)
    $candidates = @($Identities.Values | Where-Object Role -EQ $IdentityRole)
    if ($candidates.Count -eq 0) { return $ManagedIdentityCaller }
    ($candidates | Get-Random).Name
}

function Select-Weighted {
    param([object[]]$Items)
    $total = ($Items | Measure-Object -Property Weight -Sum).Sum
    $roll = Get-Random -Minimum 0.0 -Maximum ([double]$total)
    foreach ($item in $Items) {
        $roll -= $item.Weight
        if ($roll -lt 0) { return $item }
    }
    $Items[-1]
}

function New-CertificatePolicy {
    param([string]$Subject, [string]$IssuerName = 'Self', [int]$ValidityMonths = 12, [int]$LifetimePercentage = 80)
    # Unknown (externally signed) issuers do not support AutoRenew.
    $lifetimeAction = if ($IssuerName -eq 'Unknown') {
        @{ trigger = @{ days_before_expiry = 30 }; action = @{ action_type = 'EmailContacts' } }
    }
    else {
        @{ trigger = @{ lifetime_percentage = $LifetimePercentage }; action = @{ action_type = 'AutoRenew' } }
    }
    @{
        key_props        = @{ exportable = $true; kty = 'RSA'; key_size = 2048; reuse_key = $false }
        secret_props     = @{ contentType = 'application/x-pkcs12' }
        x509_props       = @{
            subject         = $Subject
            sans            = @{ dns_names = @($Subject.Substring(3)) }
            validity_months = $ValidityMonths
            key_usage       = @('digitalSignature', 'keyEncipherment')
            ekus            = @('1.3.6.1.5.5.7.3.1')
        }
        issuer           = @{ name = $IssuerName }
        lifetime_actions = @($lifetimeAction)
    }
}

function Get-RotationPolicy {
    param([int]$RotateAfterDays = 7)
    @{
        lifetimeActions = @(
            @{ trigger = @{ timeAfterCreate = "P$($RotateAfterDays)D" }; action = @{ type = 'Rotate' } }
            @{ trigger = @{ timeBeforeExpiry = 'P10D' }; action = @{ type = 'Notify' } }
        )
        attributes      = @{ expiryTime = 'P28D' }
    }
}

function New-LocalPfx {
    param([string]$Subject, [datetime]$NotAfter, [string]$Password)
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-10), [DateTimeOffset]::new($NotAfter.ToUniversalTime()))
    [Convert]::ToBase64String($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password))
}

function Import-LocalCertificate {
    param([object]$Vault, [string]$Name, [datetime]$NotAfter, [hashtable]$Tags = @{ kvlab = 'imported' })
    $password = ConvertTo-Base64Url (Get-RandomBytes 18)
    $body = @{
        value  = New-LocalPfx -Subject "CN=$Name.contoso.example" -NotAfter $NotAfter -Password $password
        pwd    = $password
        policy = @{ secret_props = @{ contentType = 'application/x-pkcs12' } }
        tags   = $Tags
    }
    Invoke-Kv $Vault POST "certificates/$Name/import" -Body $body -Operation CertificateImport
}

function New-RsaJwk {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $p = $rsa.ExportParameters($true)
    @{
        kty     = 'RSA'
        key_ops = @('encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'sign', 'verify')
        n       = ConvertTo-Base64Url $p.Modulus
        e       = ConvertTo-Base64Url $p.Exponent
        d       = ConvertTo-Base64Url $p.D
        p       = ConvertTo-Base64Url $p.P
        q       = ConvertTo-Base64Url $p.Q
        dp      = ConvertTo-Base64Url $p.DP
        dq      = ConvertTo-Base64Url $p.DQ
        qi      = ConvertTo-Base64Url $p.InverseQ
    }
}

function Get-LabCa {
    if ($script:LabCa) { return $script:LabCa }
    $key = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=KvAuditLab Partner CA', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign', $true))
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(2))
    $script:LabCa = [pscustomobject]@{ Certificate = $certificate; Key = $key }
    $script:LabCa
}

function New-CertificateFromCsr {
    param([string]$CsrBase64, [string]$Subject)
    $ca = Get-LabCa
    $der = [Convert]::FromBase64String(($CsrBase64 -replace '-----[^-]+-----', '' -replace '\s', ''))

    # PKCS#10: SEQ { SEQ { version, subject, SubjectPublicKeyInfo, attributes }, sigAlg, signature }
    $reader = [System.Formats.Asn1.AsnReader]::new([System.ReadOnlyMemory[byte]]::new($der), [System.Formats.Asn1.AsnEncodingRules]::DER)
    $requestInfo = $reader.ReadSequence().ReadSequence()
    $null = $requestInfo.ReadInteger()
    $null = $requestInfo.ReadEncodedValue()
    $spki = $requestInfo.ReadSequence()
    $algorithm = $spki.ReadSequence()
    $oid = $algorithm.ReadObjectIdentifier()
    $parameters = if ($algorithm.HasData) { $algorithm.ReadEncodedValue().ToArray() } else { [byte[]](5, 0) }
    $unusedBits = 0
    $keyBytes = $spki.ReadBitString([ref]$unusedBits)

    $publicKey = [System.Security.Cryptography.X509Certificates.PublicKey]::new(
        [System.Security.Cryptography.Oid]::new($oid),
        [System.Security.Cryptography.AsnEncodedData]::new($parameters),
        [System.Security.Cryptography.AsnEncodedData]::new($keyBytes))
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject), $publicKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false))
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment', $true))
    $ekus = [System.Security.Cryptography.OidCollection]::new()
    $null = $ekus.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekus, $false))

    $serial = Get-RandomBytes 16
    $serial[0] = $serial[0] -band 0x7F
    $generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($ca.Key, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $leaf = $request.Create($ca.Certificate.SubjectName, $generator, [DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddYears(1), $serial)
    @([Convert]::ToBase64String($leaf.RawData), [Convert]::ToBase64String($ca.Certificate.RawData))
}

function Get-KeyVersion {
    param([object]$Vault, [string]$Name, [string]$Caller)
    $key = Invoke-Kv $Vault GET "keys/$Name" -Caller $Caller -Operation KeyGet
    $key.Data.key.kid.Split('/')[-1]
}
#endregion

#region Vault lifecycle
function Invoke-VaultRecover {
    param([object]$Vault)
    $body = @{ location = $Vault.location; properties = @{ tenantId = $TenantId; sku = @{ family = 'A'; name = 'standard' }; createMode = 'recover' } }
    $null = Invoke-Arm $Vault PUT -Body $body -Operation VaultRecover
    Wait-Until -TimeoutSeconds 300 -IntervalSeconds 15 -Description "vault $($Vault.name) recovery" -Condition {
        $state = Invoke-Arm $Vault GET -Operation VaultGet -AllowedStatus 404
        $state.StatusCode -eq 200 -and $state.Data.properties.provisioningState -eq 'Succeeded'
    }
}

function Get-DeletedVaultStatus {
    param([object]$Vault)
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/locations/$($Vault.location)/deletedVaults/$($Vault.name)"
    (Invoke-KvRequest -Method GET -Uri $uri -Audience Arm -Operation 'DeletedVaultGet' -VaultName $Vault.name -AllowedStatus 404).StatusCode
}

function Confirm-VaultAvailable {
    param([object]$Vault)
    $state = Invoke-Arm $Vault GET -Operation VaultGet -AllowedStatus 404
    if ($state.StatusCode -eq 200) { return }
    if ((Get-DeletedVaultStatus $Vault) -eq 200) {
        Write-Output "Vault $($Vault.name) found in soft-deleted state; recovering."
        Invoke-VaultRecover $Vault
        return
    }
    $null = $script:UnavailableVaults.Add($Vault.name)
    Write-Warning "Vault $($Vault.name) does not exist and is not soft-deleted; it is excluded from this run."
}

function Update-VaultBaseline {
    param([object]$Vault)
    $cutoff = Get-UnixTime ([datetime]::UtcNow.AddDays(-1))
    $collections = @(
        @{ Kind = 'keys'; Prefix = 'Key'; Names = @($BaselineKeys.Name) }
        @{ Kind = 'secrets'; Prefix = 'Secret'; Names = $BaselineSecrets }
        @{ Kind = 'certificates'; Prefix = 'Certificate'; Names = @($BaselineCertificates.Name) }
    )
    foreach ($collection in $collections) {
        $kind = $collection.Kind
        $prefix = $collection.Prefix
        $items = Get-KvCollection -Vault $Vault -Path $kind -Operation "$($prefix)List"
        $existing = @($items | ForEach-Object { Get-ItemName $_ })

        foreach ($name in $collection.Names | Where-Object { $existing -notcontains $_ }) {
            $deleted = Invoke-Kv $Vault GET "deleted$kind/$name" -Operation "$($prefix)GetDeleted" -AllowedStatus 404
            if ($deleted.StatusCode -eq 200) {
                $null = Invoke-Kv $Vault POST "deleted$kind/$name/recover" -Operation "$($prefix)Recover"
                continue
            }
            switch ($kind) {
                'keys' {
                    $definition = $BaselineKeys | Where-Object { $_.Name -eq $name }
                    $null = Invoke-Kv $Vault POST "keys/$name/create" -Body ($definition.Body + @{ tags = @{ kvlab = 'baseline' } }) -Operation KeyCreate
                    if ($definition.Rotation) {
                        $null = Invoke-Kv $Vault PUT "keys/$name/rotationpolicy" -Body (Get-RotationPolicy) -Operation KeyRotationPolicySet
                    }
                }
                'secrets' {
                    $body = @{ value = ConvertTo-Base64Url (Get-RandomBytes 32); contentType = 'text/plain'; tags = @{ kvlab = 'baseline' } }
                    $null = Invoke-Kv $Vault PUT "secrets/$name" -Body $body -Operation SecretSet
                }
                'certificates' {
                    $definition = $BaselineCertificates | Where-Object { $_.Name -eq $name }
                    $policy = New-CertificatePolicy -Subject $definition.Subject -ValidityMonths $definition.ValidityMonths -LifetimePercentage $definition.LifetimePercentage
                    $null = Invoke-Kv $Vault POST "certificates/$name/create" -Body @{ policy = $policy; tags = @{ kvlab = 'baseline' } } -Operation CertificateCreate
                }
            }
        }

        # Expiry-test objects have already produced their events one day after expiring.
        $stale = @($items | Where-Object { $_.tags.kvlab -eq 'expiry-test' -and $_.attributes.exp -and $_.attributes.exp -lt $cutoff })
        foreach ($item in $stale) {
            $name = Get-ItemName $item
            $null = Invoke-Kv $Vault DELETE "$kind/$name" -Operation "$($prefix)Delete"
            Wait-Until -Description "deleted $kind/$name" -Condition {
                (Invoke-Kv $Vault GET "deleted$kind/$name" -Operation "$($prefix)GetDeleted" -AllowedStatus 404).StatusCode -eq 200
            }
            $null = Invoke-Kv $Vault DELETE "deleted$kind/$name" -Operation "$($prefix)Purge"
        }
    }

    $contacts = Invoke-Kv $Vault GET 'certificates/contacts' -Operation CertificateContactsGet -AllowedStatus 404
    if ($contacts.StatusCode -eq 404) { Set-LabContacts $Vault }
    $issuer = Invoke-Kv $Vault GET "certificates/issuers/$LabIssuerName" -Operation CertificateIssuerGet -AllowedStatus 404
    if ($issuer.StatusCode -eq 404) { Set-LabIssuer $Vault -Method PUT -Operation CertificateIssuerSet }
}

function Set-LabContacts {
    param([object]$Vault)
    $body = @{ contacts = @(@{ email = 'secops@contoso.example'; name = 'SecOps'; phone = '555-0100' }) }
    $null = Invoke-Kv $Vault PUT 'certificates/contacts' -Body $body -Operation CertificateContactsSet
}

function Set-LabIssuer {
    param([object]$Vault, [string]$Method, [string]$Operation)
    $body = @{
        provider    = 'DigiCert'
        credentials = @{ account_id = 'kvlab-account'; pwd = ConvertTo-Base64Url (Get-RandomBytes 18) }
        org_details = @{ admin_details = @(@{ first_name = 'Key'; last_name = 'Vault'; email = 'pki@contoso.example'; phone = '555-0101' }) }
        attributes  = @{ enabled = $true }
    }
    $null = Invoke-Kv $Vault $Method "certificates/issuers/$LabIssuerName" -Body $body -Operation $Operation
}
#endregion

#region Activities
function Invoke-SignVerify {
    param([object]$Vault)
    $caller = Get-Caller 'App'
    $name = 'app-signing-key', 'app-ec-key', 'app-encryption-key' | Get-Random
    $alg = if ($name -eq 'app-ec-key') { 'ES256' } else { 'RS256' }
    $version = Get-KeyVersion $Vault $name $caller
    $digest = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::HashData((Get-RandomBytes 64)))
    $signature = Invoke-Kv $Vault POST "keys/$name/$version/sign" -Body @{ alg = $alg; value = $digest } -Caller $caller -Operation KeySign
    $null = Invoke-Kv $Vault POST "keys/$name/$version/verify" -Body @{ alg = $alg; digest = $digest; value = $signature.Data.value } -Caller $caller -Operation KeyVerify
}

function Invoke-EncryptDecrypt {
    param([object]$Vault)
    $caller = Get-Caller 'App'
    $version = Get-KeyVersion $Vault 'app-encryption-key' $caller
    $cipher = Invoke-Kv $Vault POST "keys/app-encryption-key/$version/encrypt" -Body @{ alg = 'RSA-OAEP-256'; value = ConvertTo-Base64Url (Get-RandomBytes 32) } -Caller $caller -Operation KeyEncrypt
    $null = Invoke-Kv $Vault POST "keys/app-encryption-key/$version/decrypt" -Body @{ alg = 'RSA-OAEP-256'; value = $cipher.Data.value } -Caller $caller -Operation KeyDecrypt
}

function Invoke-WrapUnwrap {
    param([object]$Vault)
    $caller = Get-Caller 'App'
    $version = Get-KeyVersion $Vault 'app-encryption-key' $caller
    $wrapped = Invoke-Kv $Vault POST "keys/app-encryption-key/$version/wrapkey" -Body @{ alg = 'RSA-OAEP-256'; value = ConvertTo-Base64Url (Get-RandomBytes 32) } -Caller $caller -Operation KeyWrap
    $null = Invoke-Kv $Vault POST "keys/app-encryption-key/$version/unwrapkey" -Body @{ alg = 'RSA-OAEP-256'; value = $wrapped.Data.value } -Caller $caller -Operation KeyUnwrap
}

function Invoke-SecretUpdate {
    param([object]$Vault)
    $name = $BaselineSecrets | Get-Random
    $secret = Invoke-Kv $Vault GET "secrets/$name" -Operation SecretGet
    $version = $secret.Data.id.Split('/')[-1]
    $body = @{ contentType = 'text/plain'; tags = @{ kvlab = 'baseline'; lastReviewed = (Get-Date).ToUniversalTime().ToString('o') } }
    $null = Invoke-Kv $Vault PATCH "secrets/$name/$version" -Body $body -Operation SecretUpdate
}

function Invoke-KeyUpdate {
    param([object]$Vault)
    $name = ($BaselineKeys | Get-Random).Name
    $version = Get-KeyVersion $Vault $name $ManagedIdentityCaller
    $null = Invoke-Kv $Vault PATCH "keys/$name/$version" -Body @{ tags = @{ kvlab = 'baseline'; lastReviewed = (Get-Date).ToUniversalTime().ToString('o') } } -Operation KeyUpdate
}

function Invoke-CertificateUpdate {
    param([object]$Vault)
    $caller = Get-Caller 'CertOps'
    $name = ($BaselineCertificates | Get-Random).Name
    $certificate = Invoke-Kv $Vault GET "certificates/$name" -Caller $caller -Operation CertificateGet
    $version = $certificate.Data.id.Split('/')[-1]
    $null = Invoke-Kv $Vault PATCH "certificates/$name/$version" -Body @{ tags = @{ kvlab = 'baseline'; owner = 'web-team' } } -Caller $caller -Operation CertificateUpdate
}

function Invoke-VaultPatch {
    param([object]$Vault)
    $current = Invoke-Arm $Vault GET -Operation VaultGet
    $tags = @{}
    foreach ($property in $current.Data.tags.psobject.Properties) { $tags[$property.Name] = $property.Value }
    $tags.LastAccessReview = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm')
    $null = Invoke-Arm $Vault PATCH -Body @{ tags = $tags } -Operation VaultPatch
}

function Invoke-VaultPut {
    param([object]$Vault)
    $current = (Invoke-Arm $Vault GET -Operation VaultGet).Data
    $properties = $current.properties | Select-Object -Property * -ExcludeProperty vaultUri, provisioningState, hsmPoolResourceId
    $tags = @{}
    foreach ($property in $current.tags.psobject.Properties) { $tags[$property.Name] = $property.Value }
    $tags.LastConfigSync = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm')
    $null = Invoke-Arm $Vault PUT -Body @{ location = $current.location; tags = $tags; properties = $properties } -Operation VaultPut
}

function Invoke-AccessPolicyChange {
    param([object]$Vault)
    if ($Vault.permissionModel -ne 'AccessPolicy' -or $Identities.Count -eq 0) {
        $null = Invoke-Arm $Vault GET -Operation VaultGet
        return
    }
    $identity = $Identities.Values | Get-Random
    $kind = 'add', 'remove' | Get-Random
    $policy = @{ tenantId = $TenantId; objectId = $identity.ObjectId; permissions = @{ keys = @(); secrets = @('backup'); certificates = @() } }
    $null = Invoke-Arm $Vault PUT "/accessPolicies/$kind" -Body @{ properties = @{ accessPolicies = @($policy) } } -Operation "VaultAccessPolicy-$kind"
}

function Invoke-ContactsChange {
    param([object]$Vault)
    $contacts = Invoke-Kv $Vault GET 'certificates/contacts' -Operation CertificateContactsGet -AllowedStatus 404
    if ($contacts.StatusCode -eq 200) { $null = Invoke-Kv $Vault DELETE 'certificates/contacts' -Operation CertificateContactsDelete }
    else { Set-LabContacts $Vault }
}

function Invoke-IssuerChange {
    param([object]$Vault)
    $issuer = Invoke-Kv $Vault GET "certificates/issuers/$LabIssuerName" -Operation CertificateIssuerGet -AllowedStatus 404
    if ($issuer.StatusCode -eq 404) { Set-LabIssuer $Vault -Method PUT -Operation CertificateIssuerSet }
    elseif ((Get-Random -Maximum 1.0) -lt 0.7) { Set-LabIssuer $Vault -Method PATCH -Operation CertificateIssuerUpdate }
    else { $null = Invoke-Kv $Vault DELETE "certificates/issuers/$LabIssuerName" -Operation CertificateIssuerDelete }
}

function Clear-PendingCertificate {
    param([object]$Vault, [string]$Name)
    $pending = Invoke-Kv $Vault GET "certificates/$Name/pending" -Operation CertificatePendingGet -AllowedStatus 404
    if ($pending.StatusCode -eq 200 -and $pending.Data.status -eq 'inProgress') {
        $null = Invoke-Kv $Vault DELETE "certificates/$Name/pending" -Operation CertificatePendingDelete
    }
}

$Activities = @(
    # Reads by applications
    [pscustomobject]@{ Name = 'SecretGet'; Weight = 18; Action = { param($v) $null = Invoke-Kv $v GET "secrets/$($BaselineSecrets | Get-Random)" -Caller (Get-Caller 'App') -Operation SecretGet } }
    [pscustomobject]@{ Name = 'SecretGetDenied'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET "secrets/$($BaselineSecrets | Get-Random)" -Caller (Get-Caller 'Reader') -Operation SecretGet -AllowedStatus 403 } }
    [pscustomobject]@{ Name = 'SecretList'; Weight = 4; Action = { param($v) $null = Get-KvCollection -Vault $v -Path 'secrets' -Operation SecretList -Caller (Get-Caller ('App', 'Reader' | Get-Random)) } }
    [pscustomobject]@{ Name = 'SecretListVersions'; Weight = 2; Action = { param($v) $null = Invoke-Kv $v GET "secrets/$($BaselineSecrets | Get-Random)/versions" -Caller (Get-Caller 'App') -Operation SecretListVersions } }
    [pscustomobject]@{ Name = 'KeyGet'; Weight = 6; Action = { param($v) $null = Invoke-Kv $v GET "keys/$(($BaselineKeys | Get-Random).Name)" -Caller (Get-Caller 'App') -Operation KeyGet } }
    [pscustomobject]@{ Name = 'KeyList'; Weight = 3; Action = { param($v) $null = Get-KvCollection -Vault $v -Path 'keys' -Operation KeyList -Caller (Get-Caller 'Reader') } }
    [pscustomobject]@{ Name = 'KeyListVersions'; Weight = 2; Action = { param($v) $null = Invoke-Kv $v GET "keys/$(($BaselineKeys | Get-Random).Name)/versions" -Caller (Get-Caller 'Reader') -Operation KeyListVersions } }
    [pscustomobject]@{ Name = 'KeyRotationPolicyGet'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'keys/rotating-key/rotationpolicy' -Operation KeyRotationPolicyGet } }
    [pscustomobject]@{ Name = 'CertificateGet'; Weight = 5; Action = { param($v) $null = Invoke-Kv $v GET "certificates/$(($BaselineCertificates | Get-Random).Name)" -Caller (Get-Caller ('CertOps', 'Reader' | Get-Random)) -Operation CertificateGet } }
    [pscustomobject]@{ Name = 'CertificateList'; Weight = 3; Action = { param($v) $null = Get-KvCollection -Vault $v -Path 'certificates' -Operation CertificateList -Caller (Get-Caller ('CertOps', 'Reader' | Get-Random)) } }
    [pscustomobject]@{ Name = 'CertificateListVersions'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET "certificates/$(($BaselineCertificates | Get-Random).Name)/versions" -Caller (Get-Caller 'CertOps') -Operation CertificateListVersions } }
    [pscustomobject]@{ Name = 'CertificatePolicyGet'; Weight = 2; Action = { param($v) $null = Invoke-Kv $v GET "certificates/$(($BaselineCertificates | Get-Random).Name)/policy" -Caller (Get-Caller 'CertOps') -Operation CertificatePolicyGet } }
    [pscustomobject]@{ Name = 'CertificateContactsGet'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'certificates/contacts' -Operation CertificateContactsGet -AllowedStatus 404 } }
    [pscustomobject]@{ Name = 'CertificateIssuerGet'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET "certificates/issuers/$LabIssuerName" -Operation CertificateIssuerGet -AllowedStatus 404 } }
    [pscustomobject]@{ Name = 'CertificateIssuersList'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'certificates/issuers' -Operation CertificateIssuersList } }
    [pscustomobject]@{ Name = 'CertificatePendingGet'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'certificates/partner-signed-tls/pending' -Operation CertificatePendingGet -AllowedStatus 404 } }
    [pscustomobject]@{ Name = 'KeyListDeleted'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'deletedkeys' -Operation KeyListDeleted } }
    [pscustomobject]@{ Name = 'SecretListDeleted'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'deletedsecrets' -Operation SecretListDeleted } }
    [pscustomobject]@{ Name = 'CertificateListDeleted'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v GET 'deletedcertificates' -Operation CertificateListDeleted } }
    [pscustomobject]@{ Name = 'VaultGet'; Weight = 3; Action = { param($v) $null = Invoke-Arm $v GET -Operation VaultGet } }
    [pscustomobject]@{ Name = 'Authentication'; Weight = 2; Action = { param($v) $null = Invoke-Kv $v GET 'secrets' -Anonymous -Caller 'anonymous' -Operation Authentication -AllowedStatus 401 } }

    # Cryptographic operations by applications
    [pscustomobject]@{ Name = 'SignVerify'; Weight = 6; Action = { param($v) Invoke-SignVerify $v } }
    [pscustomobject]@{ Name = 'EncryptDecrypt'; Weight = 5; Action = { param($v) Invoke-EncryptDecrypt $v } }
    [pscustomobject]@{ Name = 'WrapUnwrap'; Weight = 5; Action = { param($v) Invoke-WrapUnwrap $v } }

    # Writes by automation / operators
    [pscustomobject]@{ Name = 'SecretSet'; Weight = 3; Action = { param($v) $null = Invoke-Kv $v PUT "secrets/$($BaselineSecrets | Get-Random)" -Body @{ value = ConvertTo-Base64Url (Get-RandomBytes 32); contentType = 'text/plain'; tags = @{ kvlab = 'baseline' } } -Operation SecretSet } }
    [pscustomobject]@{ Name = 'SecretUpdate'; Weight = 1; Action = { param($v) Invoke-SecretUpdate $v } }
    [pscustomobject]@{ Name = 'KeyCreate'; Weight = 1; Action = { param($v) $definition = $BaselineKeys | Where-Object { -not $_.Rotation } | Get-Random; $null = Invoke-Kv $v POST "keys/$($definition.Name)/create" -Body ($definition.Body + @{ tags = @{ kvlab = 'baseline' } }) -Operation KeyCreate } }
    [pscustomobject]@{ Name = 'KeyImport'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v PUT 'keys/imported-key' -Body @{ key = New-RsaJwk; tags = @{ kvlab = 'imported' } } -Operation KeyImport } }
    [pscustomobject]@{ Name = 'KeyUpdate'; Weight = 1; Action = { param($v) Invoke-KeyUpdate $v } }
    [pscustomobject]@{ Name = 'KeyRotate'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v POST 'keys/rotating-key/rotate' -Operation KeyRotate } }
    [pscustomobject]@{ Name = 'KeyRotationPolicySet'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v PUT 'keys/rotating-key/rotationpolicy' -Body (Get-RotationPolicy -RotateAfterDays (Get-Random -Minimum 7 -Maximum 15)) -Operation KeyRotationPolicySet } }
    [pscustomobject]@{ Name = 'CertificateCreate'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v POST 'certificates/web-tls/create' -Body @{ policy = New-CertificatePolicy -Subject 'CN=web.contoso.example'; tags = @{ kvlab = 'baseline' } } -Operation CertificateCreate } }
    [pscustomobject]@{ Name = 'CertificateImport'; Weight = 1; Action = { param($v) $null = Import-LocalCertificate -Vault $v -Name 'imported-tls' -NotAfter ([datetime]::UtcNow.AddYears(1)) } }
    [pscustomobject]@{ Name = 'CertificateUpdate'; Weight = 1; Action = { param($v) Invoke-CertificateUpdate $v } }
    [pscustomobject]@{ Name = 'CertificatePolicyUpdate'; Weight = 1; Action = { param($v) $null = Invoke-Kv $v PATCH 'certificates/web-tls/policy' -Body @{ lifetime_actions = @(@{ trigger = @{ lifetime_percentage = (Get-Random -Minimum 70 -Maximum 91) }; action = @{ action_type = 'AutoRenew' } }) } -Caller (Get-Caller 'CertOps') -Operation CertificatePolicyUpdate } }

    # Administrative changes
    [pscustomobject]@{ Name = 'VaultPatch'; Weight = 1; Action = { param($v) Invoke-VaultPatch $v } }
    [pscustomobject]@{ Name = 'VaultPut'; Weight = 0.5; Action = { param($v) Invoke-VaultPut $v } }
    [pscustomobject]@{ Name = 'AccessPolicyChange'; Weight = 1; Action = { param($v) Invoke-AccessPolicyChange $v } }
    [pscustomobject]@{ Name = 'ContactsChange'; Weight = 0.5; Action = { param($v) Invoke-ContactsChange $v } }
    [pscustomobject]@{ Name = 'IssuerChange'; Weight = 0.5; Action = { param($v) Invoke-IssuerChange $v } }
)
#endregion

#region Scenarios
$ObjectKinds = @(
    @{ Kind = 'keys'; Prefix = 'Key'; Names = { ($BaselineKeys | Get-Random).Name } }
    @{ Kind = 'secrets'; Prefix = 'Secret'; Names = { $BaselineSecrets | Get-Random } }
    @{ Kind = 'certificates'; Prefix = 'Certificate'; Names = { ($BaselineCertificates | Get-Random).Name } }
)

function Wait-ObjectDeleted {
    param([object]$Vault, [string]$Kind, [string]$Prefix, [string]$Name)
    Wait-Until -Description "deleted $Kind/$Name" -Condition {
        (Invoke-Kv $Vault GET "deleted$Kind/$Name" -Operation "$($Prefix)GetDeleted" -AllowedStatus 404).StatusCode -eq 200
    }
}

function Invoke-SoftDeleteRecoverScenario {
    param([object]$Vault)
    $target = $ObjectKinds | Get-Random
    $kind = $target.Kind; $prefix = $target.Prefix; $name = & $target.Names
    Write-Output "Scenario: soft delete + recover $kind/$name in $($Vault.name)"
    $null = Invoke-Kv $Vault DELETE "$kind/$name" -Operation "$($prefix)Delete"
    Wait-ObjectDeleted -Vault $Vault -Kind $kind -Prefix $prefix -Name $name
    $null = Invoke-Kv $Vault GET "deleted$kind" -Operation "$($prefix)ListDeleted"
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 60)
    $null = Invoke-Kv $Vault POST "deleted$kind/$name/recover" -Operation "$($prefix)Recover"
    Wait-Until -Description "recovered $kind/$name" -Condition {
        (Invoke-Kv $Vault GET "$kind/$name" -Operation "$($prefix)Get" -AllowedStatus 404).StatusCode -eq 200
    }
}

function Invoke-PurgeRestoreScenario {
    param([object]$Vault)
    $target = $ObjectKinds | Get-Random
    $kind = $target.Kind; $prefix = $target.Prefix; $name = & $target.Names
    Write-Output "Scenario: backup + delete + purge + restore $kind/$name in $($Vault.name)"
    $backup = (Invoke-Kv $Vault POST "$kind/$name/backup" -Operation "$($prefix)Backup").Data.value
    $null = Invoke-Kv $Vault DELETE "$kind/$name" -Operation "$($prefix)Delete"
    Wait-ObjectDeleted -Vault $Vault -Kind $kind -Prefix $prefix -Name $name
    $null = Invoke-Kv $Vault DELETE "deleted$kind/$name" -Operation "$($prefix)Purge"
    Wait-Until -Description "purged $kind/$name" -Condition {
        (Invoke-Kv $Vault GET "deleted$kind/$name" -Operation "$($prefix)GetDeleted" -AllowedStatus 404).StatusCode -eq 404
    }
    # Restore returns 409 until the purge has fully completed.
    Wait-Until -TimeoutSeconds 300 -IntervalSeconds 15 -Description "restore of $kind/$name" -Condition {
        (Invoke-Kv $Vault POST "$kind/restore" -Body @{ value = $backup } -Operation "$($prefix)Restore" -AllowedStatus 409).StatusCode -lt 300
    }
}

function Invoke-PendingMergeScenario {
    param([object]$Vault)
    $name = 'partner-signed-tls'
    $subject = 'CN=partner.contoso.example'
    Write-Output "Scenario: externally signed certificate (CSR + merge) $name in $($Vault.name)"
    Clear-PendingCertificate -Vault $Vault -Name $name
    $created = Invoke-Kv $Vault POST "certificates/$name/create" -Body @{ policy = New-CertificatePolicy -Subject $subject -IssuerName 'Unknown'; tags = @{ kvlab = 'partner' } } -Operation CertificateCreate
    $pending = Invoke-Kv $Vault GET "certificates/$name/pending" -Operation CertificatePendingGet
    $csr = if ($pending.Data.csr) { $pending.Data.csr } else { $created.Data.csr }
    $chain = New-CertificateFromCsr -CsrBase64 $csr -Subject $subject
    $null = Invoke-Kv $Vault POST "certificates/$name/pending/merge" -Body @{ x5c = $chain } -Operation CertificatePendingMerge
}

function Invoke-PendingCancelScenario {
    param([object]$Vault)
    $name = 'pending-cancel-tls'
    Write-Output "Scenario: certificate request cancelled $name in $($Vault.name)"
    Clear-PendingCertificate -Vault $Vault -Name $name
    $null = Invoke-Kv $Vault POST "certificates/$name/create" -Body @{ policy = New-CertificatePolicy -Subject 'CN=cancelled.contoso.example' -IssuerName 'Unknown' } -Operation CertificateCreate
    $null = Invoke-Kv $Vault GET "certificates/$name/pending" -Operation CertificatePendingGet
    $null = Invoke-Kv $Vault PATCH "certificates/$name/pending" -Body @{ cancellation_requested = $true } -Operation CertificatePendingUpdate -AllowedStatus 400, 409
    $null = Invoke-Kv $Vault DELETE "certificates/$name/pending" -Operation CertificatePendingDelete -AllowedStatus 404
}

function Invoke-VaultDeleteRecoverScenario {
    param([object]$Vault)
    Write-Output "Scenario: vault delete + recover $($Vault.name)"
    $null = $script:UnavailableVaults.Add($Vault.name)
    $null = Invoke-Arm $Vault GET -Operation VaultGet
    $null = Invoke-Arm $Vault DELETE -Operation VaultDelete
    Wait-Until -TimeoutSeconds 300 -IntervalSeconds 15 -Description "vault $($Vault.name) soft delete" -Condition {
        (Get-DeletedVaultStatus $Vault) -eq 200
    }
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 180)
    Invoke-VaultRecover $Vault
    $null = $script:UnavailableVaults.Remove($Vault.name)
}

function Invoke-ExpiryScenario {
    param([object]$Vault)
    Write-Output "Scenario: near-expiry and expiring objects in $($Vault.name)"
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmm')
    $tags = @{ kvlab = 'expiry-test' }
    $near = [datetime]::UtcNow.AddDays(20)
    $soon = [datetime]::UtcNow.AddMinutes(15)

    foreach ($entry in @(@{ Label = 'near-expiry'; Exp = $near }, @{ Label = 'expiring'; Exp = $soon })) {
        $exp = Get-UnixTime $entry.Exp
        $null = Invoke-Kv $Vault PUT "secrets/$($entry.Label)-secret-$stamp" -Body @{ value = ConvertTo-Base64Url (Get-RandomBytes 24); attributes = @{ exp = $exp }; tags = $tags } -Operation SecretSet
        $null = Invoke-Kv $Vault POST "keys/$($entry.Label)-key-$stamp/create" -Body @{ kty = 'RSA'; key_size = 2048; attributes = @{ exp = $exp }; tags = $tags } -Operation KeyCreate
        $null = Import-LocalCertificate -Vault $Vault -Name "$($entry.Label)-cert-$stamp" -NotAfter $entry.Exp -Tags $tags
    }
}

$Scenarios = @(
    [pscustomobject]@{ Name = 'SoftDeleteRecover'; Weight = 4; Action = { param($v) Invoke-SoftDeleteRecoverScenario $v } }
    [pscustomobject]@{ Name = 'PurgeRestore'; Weight = 2; Action = { param($v) Invoke-PurgeRestoreScenario $v } }
    [pscustomobject]@{ Name = 'PendingMerge'; Weight = 1; Action = { param($v) Invoke-PendingMergeScenario $v } }
    [pscustomobject]@{ Name = 'PendingCancel'; Weight = 1; Action = { param($v) Invoke-PendingCancelScenario $v } }
)
#endregion

#region Main
$started = [DateTime]::UtcNow
$deadline = $started.AddMinutes($DurationMinutes)
Write-Output "KvAuditLab simulation started $($started.ToString('o')) for $DurationMinutes minute(s) across $($Vaults.Count) vault(s) with $($Identities.Count) app identities."

foreach ($vault in $Vaults) {
    try {
        Confirm-VaultAvailable $vault
        if (-not $script:UnavailableVaults.Contains($vault.name)) { Update-VaultBaseline $vault }
    }
    catch { Write-Warning "Baseline for $($vault.name) failed: $($_.Exception.Message)" }
}

$churnVault = $Vaults | Where-Object role -EQ 'Churn' | Select-Object -First 1
$churnAt = $null
if ($churnVault -and (Get-Random -Maximum 1.0) -lt $VaultChurnProbability) {
    $churnAt = $started.AddMinutes((Get-Random -Minimum 1 -Maximum ([math]::Max(2, $DurationMinutes - 10))))
}
$expiryPending = (Get-Random -Maximum 1.0) -lt $ExpiryScenarioProbability
$printed = 0

while ([DateTime]::UtcNow -lt $deadline) {
    $available = @($Vaults | Where-Object { -not $script:UnavailableVaults.Contains($_.name) })
    if ($available.Count -eq 0) { Write-Warning 'No vaults available.'; break }
    $vault = $available | Get-Random

    try {
        if ($churnAt -and [DateTime]::UtcNow -ge $churnAt) {
            $churnAt = $null
            Invoke-VaultDeleteRecoverScenario $churnVault
        }
        elseif ($expiryPending) {
            $expiryPending = $false
            Invoke-ExpiryScenario $vault
        }
        elseif ((Get-Random -Maximum 1.0) -lt $DestructiveScenarioProbability) {
            & (Select-Weighted $Scenarios).Action $vault
        }
        else {
            $null = & (Select-Weighted $Activities).Action $vault
        }
    }
    catch {
        Write-Warning $_.Exception.Message
    }

    for (; $printed -lt $script:Activity.Count; $printed++) {
        $a = $script:Activity[$printed]
        Write-Output ('{0:HH:mm:ss} {1,-26} {2,-24} {3,-28} {4} {5}' -f $a.Time, $a.Operation, $a.Vault, $a.Caller, $a.Status, $a.RequestId)
    }

    $remaining = ($deadline - [DateTime]::UtcNow).TotalSeconds
    if ($remaining -le 0) { break }
    $delay = Get-Random -Minimum $MinDelaySeconds -Maximum ([math]::Max($MinDelaySeconds + 1, $MaxDelaySeconds + 1))
    Start-Sleep -Seconds ([math]::Min($delay, [math]::Ceiling($remaining)))
}

# A churn vault must never be left deleted.
if ($churnVault -and $script:UnavailableVaults.Contains($churnVault.name)) {
    try { Confirm-VaultAvailable $churnVault } catch { Write-Warning "Recovery of $($churnVault.name) failed: $($_.Exception.Message)" }
}

Write-Output ''
Write-Output "Simulation finished. $($script:Activity.Count) request(s) issued."
$script:Activity |
    Group-Object Operation |
    Sort-Object Name |
    ForEach-Object {
        [pscustomobject]@{
            Operation = $_.Name
            Requests  = $_.Count
            Errors    = @($_.Group | Where-Object Status -GE 400).Count
        }
    } |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Output
#endregion
