$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Start-Transcript -Path C:\Windows\Temp\libtpms-bootstrap.log -Force
try {
    $virtio = Get-PSDrive -PSProvider FileSystem | Where-Object {
        Test-Path (Join-Path $_.Root 'guest-agent\qemu-ga-x86_64.msi')
    } | Select-Object -First 1
    if (-not $virtio) { throw 'Verified VirtIO CD with qemu-ga-x86_64.msi was not found' }

    foreach ($driver in @('NetKVM\w11\amd64\netkvm.inf', 'vioserial\w11\amd64\vioser.inf')) {
        $path = Join-Path $virtio.Root $driver
        if (-not (Test-Path $path)) { throw "VirtIO driver missing: $driver" }
        & pnputil.exe /add-driver $path /install
        if ($LASTEXITCODE -notin @(0, 3010)) { throw "Driver installation failed: $driver ($LASTEXITCODE)" }
    }
    $msi = Join-Path $virtio.Root 'guest-agent\qemu-ga-x86_64.msi'
    $install = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', 'C:\Windows\Temp\qemu-ga-install.log') -Wait -PassThru
    if ($install.ExitCode -notin @(0, 3010)) { throw "QEMU agent installation failed: $($install.ExitCode)" }
    Set-Service QEMU-GA -StartupType Automatic
    Start-Service QEMU-GA

    # The host forwards WinRM only on loopback; this enables Packer's temporary
    # provisioning connection on the isolated QEMU user-mode network.
    # This Windows image rejects AllowUnencrypted on a Public profile even when the
    # listener was created with SkipNetworkProfileCheck. Wait for the new VirtIO
    # adapter's profile, then classify this isolated network as Private.
    $deadline = (Get-Date).AddMinutes(2)
    do {
        $connected = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty InterfaceIndex)
        $profiles = @(Get-NetConnectionProfile | Where-Object { $_.InterfaceIndex -in $connected })
        if ($profiles.Count -gt 0) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ($profiles.Count -eq 0) { throw 'No connected network profile appeared after VirtIO driver installation' }
    foreach ($profile in $profiles) {
        if ($profile.NetworkCategory -eq 'Public') {
            Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private
        }
    }
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
    New-NetFirewallRule -DisplayName 'Packer WinRM' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -Profile Any | Out-Null
    Set-Service WinRM -StartupType Automatic
    Restart-Service WinRM
    # Enable Packer's transport last, after the service restart has completed.
    & winrm.cmd set winrm/config/service/auth '@{Basic="true"}'
    if ($LASTEXITCODE -ne 0) { throw "Enabling WinRM Basic authentication failed ($LASTEXITCODE)" }
    & winrm.cmd set winrm/config/service '@{AllowUnencrypted="true"}'
    if ($LASTEXITCODE -ne 0) { throw "Enabling WinRM unencrypted transport failed ($LASTEXITCODE)" }
} finally {
    Stop-Transcript
}
