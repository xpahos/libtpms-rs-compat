# Runs once as a SYSTEM scheduled task started by Packer's shutdown_command, after the
# final remote checks. It removes provisioning-only WinRM access, records the outcome,
# and powers off. On failure the guest stays up, so Packer's shutdown timeout fails the build.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$outcome = 'C:\libtpms-integration\finalize.json'
try {
    Start-Sleep -Seconds 5
    & winrm.cmd set winrm/config/service/auth '@{Basic="false"}' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Disabling WinRM Basic authentication failed ($LASTEXITCODE)" }
    & winrm.cmd set winrm/config/service '@{AllowUnencrypted="false"}' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Disabling WinRM unencrypted transport failed ($LASTEXITCODE)" }
    & winrm.cmd delete 'winrm/config/Listener?Address=*+Transport=HTTP' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Deleting the WinRM HTTP listener failed ($LASTEXITCODE)" }
    Get-NetFirewallRule -DisplayName 'Packer WinRM' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
        -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
    Set-Service WinRM -StartupType Disabled
    Stop-Service WinRM -Force
    Remove-Item C:\Windows\Temp\libtpms-identity.json -Force -ErrorAction SilentlyContinue

    $wsman = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'
    $settings = Get-ItemProperty "$wsman\Service" -ErrorAction SilentlyContinue
    $service = Get-Service WinRM
    $state = [ordered]@{
        winrm_service_start = $service.StartType.ToString()
        winrm_service_status = $service.Status.ToString()
        winrm_listeners = @(Get-ChildItem "$wsman\Listener" -ErrorAction SilentlyContinue).Count
        winrm_basic_auth = [bool]($settings.auth_basic -eq 1)
        winrm_allow_unencrypted = [bool]($settings.allow_unencrypted -eq 1)
        packer_firewall_rules = @(Get-NetFirewallRule -DisplayName 'Packer WinRM' -ErrorAction SilentlyContinue).Count
        enabled_winrm_firewall_rules = @(Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' }).Count
    }
    if ($state.winrm_service_start -ne 'Disabled' -or $state.winrm_service_status -ne 'Stopped' -or
        $state.winrm_listeners -or $state.winrm_basic_auth -or $state.winrm_allow_unencrypted -or
        $state.packer_firewall_rules -or $state.enabled_winrm_firewall_rules) {
        throw "Provisioning WinRM access remains: $($state | ConvertTo-Json -Compress)"
    }
    [ordered]@{ status = 'PASS'; completed_at = (Get-Date).ToUniversalTime().ToString('o'); state = $state } |
        ConvertTo-Json -Compress | Set-Content -Encoding ASCII $outcome
    & schtasks.exe /Delete /TN libtpms-finalize /F | Out-Null
    Remove-Item -LiteralPath $PSCommandPath -Force
    & shutdown.exe /s /t 0 /f /d p:4:1
} catch {
    @{ status = 'FAIL'; error = $_.Exception.Message } | ConvertTo-Json -Compress | Set-Content -Encoding ASCII $outcome
    exit 1
}
