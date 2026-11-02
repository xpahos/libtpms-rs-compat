$ErrorActionPreference = 'Stop'
Set-Service QEMU-GA -StartupType Automatic
Start-Service QEMU-GA
if (-not (Get-Tpm).TpmPresent) { throw 'TPM 2.0 device is absent' }
if (-not (Test-Path 'C:\libtpms-integration\probe.ps1')) { throw 'Integration probe is absent' }

# Keep base images free of TPM-bound BitLocker secrets and unattended passwords.
$volume = Get-BitLockerVolume -MountPoint C:
if ($volume.VolumeStatus -ne 'FullyDecrypted') { throw 'Base image unexpectedly has device encryption enabled' }
$logon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $logon -Name AutoAdminLogon -Value '0'
Remove-ItemProperty -Path $logon -Name DefaultPassword -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $logon -Name AutoLogonCount -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Panther\Unattend.xml,C:\Windows\Panther\Unattend\Unattend.xml,C:\Windows\System32\Sysprep\unattend.xml -Force -ErrorAction SilentlyContinue
Set-LocalUser -Name packer -PasswordNeverExpires $true
