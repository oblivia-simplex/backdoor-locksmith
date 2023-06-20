#! /usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
[ -d "$SCRIPT_DIR/fw" ] || bash "${SCRIPT_DIR}/getfw.sh"

cd "$SCRIPT_DIR"

IFS=$'\t'
info=($(cat telnetd_startup_paths.txt | fzf))

echo "Firmware: ${info[0]}"
echo "telnetd_startup path: ${info[1]}"
echo "QEMU: ${info[2]}"
echo "QEMU args: ${info[3]}"

firmware=${info[0]}
telnetd_startup=${info[1]}
qemu=${info[2]}
qemu_args=${info[3]}


cd fw/${firmware}
cmd="sudo chroot . ${qemu} $qemu_args ${telnetd_startup}"
echo "Command: $cmd"
echo $cmd | sh
