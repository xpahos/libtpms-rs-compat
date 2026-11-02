# Microsoft Platform Crypto Provider signing-key probe, run as SYSTEM through QEMU Guest Agent.
# Usage: probe.ps1 setup|verify|create-secondary|verify-secondary <64 hex challenge>
#        probe.ps1 remove-secondary   or   probe.ps1 identity
# Output is one JSON object. Signing actions return the key's public part as base64 DER
# X.509 SubjectPublicKeyInfo and a raw RSASSA-PKCS1-v1_5 SHA-256 signature over the
# challenge bytes, so the host can verify both independently. Only setup and
# create-secondary create keys; remove-secondary deletes the secondary key for negative checks only.
param(
    [Parameter(Mandatory=$true)][ValidateSet('setup', 'verify', 'create-secondary', 'verify-secondary', 'remove-secondary', 'identity')][string]$Action,
    [string]$Challenge = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-BootId {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters').BootId.ToString()
}

function Get-DerLength([int]$Length) {
    if ($Length -lt 0x80) { return [byte[]]@($Length) }
    $bytes = [System.Collections.Generic.List[byte]]::new()
    while ($Length -gt 0) { $bytes.Insert(0, [byte]($Length -band 0xff)); $Length = $Length -shr 8 }
    return [byte[]](@([byte](0x80 -bor $bytes.Count)) + $bytes.ToArray())
}

function Get-Der([byte]$Tag, [byte[]]$Content) {
    return [byte[]](@($Tag) + (Get-DerLength $Content.Length) + $Content)
}

function Get-DerInteger([byte[]]$Unsigned) {
    $start = 0
    while ($start -lt $Unsigned.Length - 1 -and $Unsigned[$start] -eq 0) { $start++ }
    [byte[]]$value = $Unsigned[$start..($Unsigned.Length - 1)]
    if ($value[0] -band 0x80) { $value = [byte[]](@([byte]0) + $value) }
    return Get-Der 0x02 $value
}

function Get-SubjectPublicKeyInfo([System.Security.Cryptography.RSAParameters]$Parameters) {
    $algorithm = Get-Der 0x30 ([byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00))
    $rsaKey = Get-Der 0x30 ([byte[]]((Get-DerInteger $Parameters.Modulus) + (Get-DerInteger $Parameters.Exponent)))
    $bitString = Get-Der 0x03 ([byte[]](@([byte]0) + $rsaKey))
    return Get-Der 0x30 ([byte[]]($algorithm + $bitString))
}

function Get-Identity {
    $current = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $service = Get-Service WinRM
    $wsman = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'
    $settings = Get-ItemProperty "$wsman\Service" -ErrorAction SilentlyContinue
    $listeners = @(Get-ChildItem "$wsman\Listener" -ErrorAction SilentlyContinue).Count
    $packerRules = @(Get-NetFirewallRule -DisplayName 'Packer WinRM' -ErrorAction SilentlyContinue).Count
    $openRules = @(Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' }).Count
    $access = [ordered]@{
        winrm_service_start = $service.StartType.ToString()
        winrm_service_status = $service.Status.ToString()
        winrm_listeners = $listeners
        winrm_basic_auth = [bool]($settings.auth_basic -eq 1)
        winrm_allow_unencrypted = [bool]($settings.allow_unencrypted -eq 1)
        packer_firewall_rules = $packerRules
        enabled_winrm_firewall_rules = $openRules
    }
    $access.exposed = [bool]($service.StartType.ToString() -ne 'Disabled' -or $service.Status.ToString() -ne 'Stopped' -or
        $listeners -gt 0 -or $access.winrm_basic_auth -or $access.winrm_allow_unencrypted -or $packerRules -gt 0 -or $openRules -gt 0)
    [ordered]@{
        status = 'PASS'; action = 'identity'; boot_id = Get-BootId
        os = [ordered]@{
            family = 'windows'; caption = $os.Caption; edition_id = $current.EditionID
            display_version = $current.DisplayVersion; current_build = $current.CurrentBuild; ubr = $current.UBR
            version = $os.Version; installation_type = $current.InstallationType
            registry_product_name = $current.ProductName
        }
        provisioning_access = $access
    }
}

function New-ProbeKey([string]$Name, $Provider) {
    $parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $parameters.Provider = $Provider
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.Parameters.Add([System.Security.Cryptography.CngProperty]::new(
        'Length', [BitConverter]::GetBytes([int]2048), [System.Security.Cryptography.CngPropertyOptions]::None))
    return [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $Name, $parameters)
}

$key = $null
$rsa = $null
try {
    if ($Action -eq 'identity') {
        if ($Challenge) { throw 'identity takes no challenge' }
        Get-Identity | ConvertTo-Json -Compress -Depth 4
        exit 0
    }
    $state = 'C:\libtpms-integration\state'
    $keys = @{
        primary = @{ name = 'libtpms-integration-signing-key'; blob = "$state\public.blob" }
        secondary = @{ name = 'libtpms-integration-secondary-key'; blob = "$state\secondary.blob" }
    }
    $role = if ($Action.EndsWith('-secondary')) { 'secondary' } else { 'primary' }
    $name = $keys[$role].name
    $blob = $keys[$role].blob
    $provider = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
    $machine = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
    if ($Action -eq 'remove-secondary') {
        if ($Challenge) { throw 'remove-secondary takes no challenge' }
        $key = [System.Security.Cryptography.CngKey]::Open($name, $provider, $machine)
        $key.Delete()
        $key = $null
        [ordered]@{ status = 'PASS'; action = $Action; boot_id = Get-BootId; key_name = $name } | ConvertTo-Json -Compress
        exit 0
    }
    if ($Challenge -notmatch '^[0-9a-fA-F]{64}$') { throw 'expected a 32-byte hex challenge' }
    if ($Action -eq 'setup') {
        if ((Test-Path $state) -or [System.Security.Cryptography.CngKey]::Exists($name, $provider, $machine)) {
            throw 'Base image already contains probe state'
        }
        $key = New-ProbeKey $name $provider
        New-Item -ItemType Directory -Path $state | Out-Null
        [IO.File]::WriteAllBytes($blob, $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob))
    } elseif ($Action -eq 'create-secondary') {
        if (-not (Test-Path $keys.primary.blob)) { throw 'Primary key state is missing; run setup first' }
        if ((Test-Path $blob) -or [System.Security.Cryptography.CngKey]::Exists($name, $provider, $machine)) {
            throw 'Secondary key already exists'
        }
        $key = New-ProbeKey $name $provider
        [IO.File]::WriteAllBytes($blob, $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob))
    } else {
        $key = [System.Security.Cryptography.CngKey]::Open($name, $provider, $machine)
    }
    if ($key.Provider.Provider -ne 'Microsoft Platform Crypto Provider') { throw 'Unexpected key provider' }
    if ($key.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None) { throw 'Key is exportable' }
    $public = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
    if ([Convert]::ToBase64String($public) -ne [Convert]::ToBase64String([IO.File]::ReadAllBytes($blob))) {
        throw "TPM $role key changed"
    }
    $bytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($Challenge.Substring($i * 2, 2), 16) }
    $rsa = [System.Security.Cryptography.RSACng]::new($key)
    $signature = $rsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                              [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    [byte[]]$spki = Get-SubjectPublicKeyInfo ($rsa.ExportParameters($false))
    [ordered]@{
        status = 'PASS'; action = $Action; challenge = $Challenge; boot_id = Get-BootId
        key_role = $role; key_name = $name; key_provider = $key.Provider.Provider
        public_key_encoding = 'x509-spki-der-base64'; public_key = [Convert]::ToBase64String($spki)
        signature_scheme = 'rsassa-pkcs1-v1_5-sha256'; signature = [Convert]::ToBase64String($signature)
    } | ConvertTo-Json -Compress
} catch {
    @{status='FAIL'; action=$Action; error=$_.Exception.Message} | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($rsa) { $rsa.Dispose() }
    if ($key) { $key.Dispose() }
}
