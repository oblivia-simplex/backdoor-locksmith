#! /usr/bin/env bash

###
# Get the tarball of Phicomm firmware images
###

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

wget https://feralmachin.es/data/fw.tgz -O- | sudo tar xz

sudo chown -R "$USER" fw/

