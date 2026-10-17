#!/usr/bin/env bash
#
# device-env.sh — find the attached YubiHSM 2 and print the two .env lines the
# compose stack needs for it.
#
#   ./device-env.sh            # inspect
#   ./device-env.sh >> .env    # use
#
# Both values are host facts that change when the device is re-enumerated (a
# replug, a reboot, a USB/IP attach), which is why they live in .env rather than
# in docker-compose.yaml: re-running this is how you follow the device.
#
# The gid matters as much as the node. udev does not run inside a container, so
# the node arrives with the ownership the host gave it, and `group_add` is the
# only way the image's non-root account (uid 65532) can open it. If the mode
# grants neither the group nor everyone read-write, this says so and points at
# the udev rule rather than leaving you to decode LIBUSB_ERROR_ACCESS from
# inside a container.
set -euo pipefail

# Yubico (1050), YubiHSM 2 (0030).
readonly VID=1050 PID=0030

node=""
for d in /sys/bus/usb/devices/*/; do
	[[ -r "$d/idVendor" && -r "$d/idProduct" ]] || continue
	[[ "$(<"$d/idVendor")" == "$VID" && "$(<"$d/idProduct")" == "$PID" ]] || continue
	node=$(printf '/dev/bus/usb/%03d/%03d' "$(<"$d/busnum")" "$(<"$d/devnum")")
	break
done

if [[ -z "$node" ]]; then
	echo "no YubiHSM 2 ($VID:$PID) is attached to this host" >&2
	exit 1
fi
if [[ ! -c "$node" ]]; then
	echo "expected a character device at $node" >&2
	exit 1
fi

gid=$(stat -c '%g' "$node")
group=$(stat -c '%G' "$node")
mode=$(stat -c '%a' "$node")

# Group rw is enough — the container is always given the node's own group — and
# so is world rw. 0600, or a mode that only grants read, is not.
if (((0$mode / 8 % 8 & 6) != 6 && (0$mode % 8 & 6) != 6)); then
	cat >&2 <<EOF
$node is mode $mode (group $group), which grants neither its group nor everyone
read-write, so the container's non-root user cannot open it. Install the udev
rule this repository ships and re-trigger it:

  sudo cp ../udev/70-yubihsm.rules /etc/udev/rules.d/
  sudo groupadd -r secsy    # or edit GROUP= in the rule
  sudo udevadm control --reload-rules
  sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=$VID
EOF
	exit 1
fi

echo "# YubiHSM 2 at $node (group $group/$gid, mode $mode), found $(date -Is)"
echo "SECSY_YUBIHSM_DEVICE=$node"
echo "SECSY_YUBIHSM_DEVICE_GID=$gid"
