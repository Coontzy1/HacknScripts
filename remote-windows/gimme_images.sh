#!/bin/bash
# Uses nc to recieve multiple sent images and decode them from raw --> base64 --> jpg?
# Press "Ctrl+C" when done to cause cleanup
# cleanup images when ctrl+c is pressed
cleanup() {
    mkdir -p output_images #OUTPUT DIR IF DOESN'T EXIST
    counter=1
    for file in received_*bin; do
            if [[ -f $file ]]; then
            base64 -d $file > "output_images/image${counter}"
        fi
    ((counter++))
    done
    rm output_images/image$((counter - 1)) #removing the last image which is just messed up nc stuff
    echo
    echo "Images should be cleaned up ;) ?"
    exit 0
}

trap cleanup SIGINT

# Check if the port number is supplied as an argument
if [[ -z "$1" ]]; then
    echo "Usage: $0 <port>"
    exit 1
fi

PORT="$1" # Set the port number from the first argument

echo "Listening on port $PORT..."

while true; do
    nc -lvp "$PORT" > "received_$(date +%s).bin"
done
