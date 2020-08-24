#!/bin/bash


export PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS/tshark"
# Parameters
socket="/var/run/usbmuxd"
dump=$1

# Extract repetition
port=9876
source_socket="$(dirname "${socket}")/$(basename "${socket}").orig"

# Move socket files
mv "${socket}" "${source_socket}"
trap "{ rm '${socket}'; mv '${source_socket}' '${socket}'; }" EXIT

# Setup pipe over TCP that we can tap into
socat -t100 "TCP-LISTEN:${port},reuseaddr,fork" "UNIX-CONNECT:${source_socket}" &
socat -t100 "UNIX-LISTEN:${socket},mode=777,reuseaddr,fork" "TCP:localhost:${port}" &

# Record traffic
tshark -i lo0 -w "${dump}" -F pcapng "dst port ${port} or src port ${port}"
