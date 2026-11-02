#!/bin/sh
set -eu
cloud-init status --wait
install -d -m 0755 /usr/local/libexec
install -m 0755 /tmp/libtpms-integration-probe /usr/local/libexec/libtpms-integration-probe
rm -f /tmp/libtpms-integration-probe
# Ubuntu's static unit is activated by the virtio guest-agent port device.
systemctl start qemu-guest-agent
systemctl is-active --quiet qemu-guest-agent
command -v tpm2_createprimary >/dev/null
command -v python3 >/dev/null
command -v openssl >/dev/null
test -c /dev/tpmrm0
