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
variable "cpus" {
  type    = number
  default = 2
}
variable "memory" {
  type    = number
  default = 4096
}
variable "machine_type" {
  type    = string
  default = "q35"
}
variable "password" {
  type      = string
  sensitive = true
}
variable "password_hash" {
  type      = string
  sensitive = true
}

source "qemu" "linux" {
  iso_url           = var.iso_url
  iso_checksum      = var.iso_checksum
  output_directory  = var.output_directory
  vm_name           = "disk.qcow2"
  format            = "qcow2"
  disk_size         = "32768M"
  disk_interface    = "virtio"
  cdrom_interface   = "ide"
  accelerator       = "kvm"
  cpu_model         = "host"
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

  # A local NoCloud CD avoids opening an HTTP seed server on the host.
  cd_label = "cidata"
  cd_content = {
    "meta-data" = "instance-id: libtpms-integration-linux\nlocal-hostname: libtpms-linux\n"
    "user-data" = templatefile("${path.root}/linux-user-data.pkrtpl", {
      password_hash = var.password_hash
    })
  }
  boot_wait = "5s"
  boot_command = [
    "<esc><wait>c<wait>",
    "linux /casper/vmlinuz autoinstall ds=nocloud ---<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  # -device replaces Packer's device list, so repeat its network device.
  # Leave -drive untouched: Packer retains the installer, seed and OVMF drives.
  qemuargs = [
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"],
    ["-device", "virtio-net-pci,netdev=user.0"],
    ["-chardev", "socket,id=integration-tpm,path=${var.tpm_socket}"],
    ["-tpmdev", "emulator,id=integration-tpm,chardev=integration-tpm"],
    ["-device", "tpm-crb,tpmdev=integration-tpm"],
    ["-device", "virtio-serial-pci,id=integration-serial"],
    ["-chardev", "null,id=integration-qga"],
    ["-device", "virtserialport,bus=integration-serial.0,chardev=integration-qga,name=org.qemu.guest_agent.0"]
  ]

  communicator           = "ssh"
  ssh_username           = "packer"
  ssh_password           = var.password
  ssh_timeout            = "45m"
  ssh_handshake_attempts = 100
  shutdown_command       = "sudo /sbin/shutdown -P now"
  shutdown_timeout       = "5m"
}

build {
  sources = ["source.qemu.linux"]
  provisioner "file" {
    source      = "${path.root}/../guest/linux-probe.py"
    destination = "/tmp/libtpms-integration-probe"
  }
  provisioner "shell" {
    script          = "${path.root}/linux-provision.sh"
    execute_command = "sudo sh '{{ .Path }}'"
  }
  provisioner "shell" {
    inline            = ["sudo reboot"]
    expect_disconnect = true
  }
  provisioner "shell" {
    pause_before = "15s"
    inline = [
      "sudo systemctl is-active --quiet qemu-guest-agent",
      "test -x /usr/local/libexec/libtpms-integration-probe",
      "test -c /dev/tpmrm0",
      "sudo /usr/local/libexec/libtpms-integration-probe identity > /tmp/libtpms-identity.json"
    ]
  }
  provisioner "file" {
    direction   = "download"
    source      = "/tmp/libtpms-identity.json"
    destination = var.identity_output
  }
}
