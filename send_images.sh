#!/bin/bash
# Script for testing sending images to my recieving script
# Directory containing files to send
SOURCE_DIR="./images"
# Destination IP and Port - Could read these in as arguments but I'm lazy so
DEST_IP="192.168.0.106"
DEST_PORT="4444"

# Loop through each file in the source directory
for file in "$SOURCE_DIR"/*; do
    if [[ -f $file ]]; then
        echo "Sending $file..."
        base64 $file | nc -q 0 $DEST_IP $DEST_PORT
        echo "File $file sent."
    fi
    sleep 1
done
