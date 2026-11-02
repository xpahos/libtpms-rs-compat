packer {
  required_version = ">= 1.14.0"
  required_plugins {
    qemu = {
      version = "= 1.1.7"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "iso_url" { type = string }
variable "iso_checksum" {
  type = string
  validation {
    condition     = can(regex("^sha256:[0-9a-fA-F]{64}$", var.iso_checksum))
    error_message = "Supply the installation ISO's explicit SHA256 as sha256:<64 hex digits>."
  }
}
variable "output_directory" { type = string }
variable "efi_firmware_code" { type = string }
variable "efi_firmware_vars" { type = string }
variable "tpm_socket" { type = string }
variable "identity_output" {
  type        = string
  description = "Host path receiving the installed guest's OS identity JSON."
}
variable "qemu_binary" {
  type    = string
  default = "qemu-system-x86_64"
}
variable "cpu_model" {
  type    = string
  default = "host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_vpindex,hv_synic,hv_time,hv_stimer"
}
variable "cpus" {
  type    = number
  default = 2
}
variable "memory" {
  type    = number
  default = 8192
}
variable "machine_type" {
  type    = string
  default = "q35"
}
variable "password" {
  type      = string
  sensitive = true
}
variable "virtio_iso_url" {
  type        = string
  description = "Local absolute path of the VirtIO ISO verified by build.py."
}
variable "virtio_iso_checksum" {
  type = string
  validation {
    condition     = can(regex("^sha256:[0-9a-fA-F]{64}$", var.virtio_iso_checksum))
    error_message = "Supply the VirtIO ISO's explicit SHA256 as sha256:<64 hex digits>."
  }
}
variable "virtio_driver_directory" {
  type        = string
  description = "Directory containing $WinPEDriver$/viostor extracted from the verified VirtIO ISO."
}
variable "windows_image_name" {
  type        = string
  description = "install.wim image name to install, e.g. \"Windows 11 Pro\"."
}
variable "windows_product_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Optional edition-selection key for installation media requiring one; does not activate Windows."
  validation {
    condition     = var.windows_product_key == "" || can(regex("^[A-Za-z0-9]{5}(-[A-Za-z0-9]{5}){4}$", var.windows_product_key))
    error_message = "Windows product key must be empty or five groups of five letters/digits separated by hyphens."
  }
}

locals {
  password_xml   = replace(replace(replace(replace(replace(var.password, "&", "&amp;"), "<", "&lt;"), ">", "&gt;"), "\"", "&quot;"), "'", "&apos;")
  image_name_xml = replace(replace(replace(var.windows_image_name, "&", "&amp;"), "<", "&lt;"), ">", "&gt;")
}

source "qemu" "windows" {
  iso_url           = var.iso_url
  iso_checksum      = var.iso_checksum
  output_directory  = var.output_directory
  vm_name           = "disk.qcow2"
  format            = "qcow2"
  disk_size         = "81920M"
  disk_interface    = "virtio"
  cdrom_interface   = "ide"
  accelerator       = "kvm"
  cpu_model         = var.cpu_model
  cpus              = var.cpus
  memory            = var.memory
  machine_type      = var.machine_type
  qemu_binary       = var.qemu_binary
  headless          = true
  vnc_bind_address  = "127.0.0.1"
  efi_boot          = true
  efi_firmware_code = var.efi_firmware_code
  efi_firmware_vars = var.efi_firmware_vars
  efi_drop_efivars  = false
  net_device        = "virtio-net-pci"

  cd_label = "integration"
  # Windows Setup automatically loads/stages boot-critical drivers from this
  # directory; no assumption about the seed CD's Windows drive letter is needed.
  cd_files = ["${var.virtio_driver_directory}/$WinPEDriver$"]
  cd_content = {
    "Autounattend.xml" = templatefile("${path.root}/windows-autounattend.pkrtpl", {
      password_xml   = local.password_xml
      image_name_xml = local.image_name_xml
      product_key    = var.windows_product_key
    })
    "bootstrap.ps1" = file("${path.root}/windows-bootstrap.ps1")
  }
  boot_wait = "1s"
  boot_command = [
    "<spacebar><wait1><spacebar><wait1><spacebar><wait1>",
    "<spacebar><wait1><spacebar><wait1><spacebar>"
  ]

  # -blockdev attaches the verified VirtIO ISO without replacing Packer's
  # installer/seed/firmware -drive arguments. q35 provides SATA port ide.2.
  qemuargs = [
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:5985"],
    ["-device", "virtio-net-pci,netdev=user.0"],
    ["-blockdev", jsonencode({ driver = "raw", "node-name" = "virtio-media", "read-only" = true, file = { driver = "file", filename = var.virtio_iso_url } })],
    ["-device", "ide-cd,drive=virtio-media,bus=ide.2"],
    ["-chardev", "socket,id=integration-tpm,path=${var.tpm_socket}"],
    ["-tpmdev", "emulator,id=integration-tpm,chardev=integration-tpm"],
    ["-device", "tpm-crb,tpmdev=integration-tpm"],
    ["-device", "virtio-serial-pci,id=integration-serial"],
    ["-chardev", "null,id=integration-qga"],
    ["-device", "virtserialport,bus=integration-serial.0,chardev=integration-qga,name=org.qemu.guest_agent.0"]
  ]

  communicator   = "winrm"
  winrm_username = "packer"
  winrm_password = var.password
  winrm_use_ssl  = false
  winrm_timeout  = "90m"
  # The SYSTEM task disables provisioning WinRM outside this WinRM session, then powers off.
  shutdown_command = "schtasks /Create /F /RU SYSTEM /RL HIGHEST /SC ONCE /ST 00:00 /TN libtpms-finalize /TR \"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\libtpms-integration\\finalize.ps1\" && schtasks /Run /TN libtpms-finalize"
  shutdown_timeout = "10m"
}

build {
  sources = ["source.qemu.windows"]
  provisioner "powershell" {
    inline = ["New-Item -ItemType Directory -Force C:\\libtpms-integration | Out-Null"]
  }
  provisioner "file" {
    source      = "${path.root}/../guest/windows-probe.ps1"
    destination = "C:/libtpms-integration/probe.ps1"
  }
  provisioner "powershell" {
    script = "${path.root}/windows-provision.ps1"
  }
  provisioner "windows-restart" {
    restart_timeout = "20m"
  }
  provisioner "powershell" {
    inline = [
      "$ErrorActionPreference = 'Stop'",
      "if ((Get-Service QEMU-GA).Status -ne 'Running') { throw 'QEMU guest agent did not start after reboot' }",
      "if (-not (Get-Tpm).TpmPresent) { throw 'TPM is absent after reboot' }",
      "if (-not (Test-Path C:\\libtpms-integration\\probe.ps1)) { throw 'Probe missing' }",
      "$identity = & C:\\libtpms-integration\\probe.ps1 identity",
      "if ($LASTEXITCODE -ne 0) { throw \"Identity probe failed: $identity\" }",
      "[IO.File]::WriteAllText('C:\\Windows\\Temp\\libtpms-identity.json', ($identity -join ''))"
    ]
  }
  provisioner "file" {
    direction   = "download"
    source      = "C:/Windows/Temp/libtpms-identity.json"
    destination = var.identity_output
  }
  provisioner "file" {
    source      = "${path.root}/windows-finalize.ps1"
    destination = "C:/libtpms-integration/finalize.ps1"
  }
}
