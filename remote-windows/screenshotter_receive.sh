#!/bin/bash
# This script will ooutput the actual jpg images recieved from the powershell screenshotting script

# Exists while loop when CTRL + C
get_me_out() {
    exit 0
}
trap get_me_out SIGINT

mkdir -p output_images

# Check if the port number is supplied as an argument
if [[ -z $1 ]]; then
    echo "Usage: $0 <port>"
    exit 1
fi

PORT=$1 # Set the port number from the first argument
echo "Listening on port $PORT..."
while true; do
   nc -lnvp "$PORT" > "output_images/received_$(date +%s).jpg"
done
