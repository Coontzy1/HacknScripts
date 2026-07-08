#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 <dest-ip> <dest-port> [source-dir]"
    echo "Example: $0 192.0.2.10 4444 ./images"
    exit 1
}

[[ $# -lt 2 ]] && usage

DEST_IP="$1"
DEST_PORT="$2"
SOURCE_DIR="${3:-./images}"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Source directory does not exist: $SOURCE_DIR"
    exit 1
fi

# Loop through each file in the source directory
for file in "$SOURCE_DIR"/*; do
    if [[ -f $file ]]; then
        echo "Sending $file..."
        base64 $file | nc -q 0 $DEST_IP $DEST_PORT
        echo "File $file sent."
    fi
    sleep 1
done
