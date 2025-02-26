#!/bin/bash
if [[ -z $1 ]]; then
    echo "$0 DEV"
    exit 1;
fi

DEV=$1
IP_ADDRESS="192.168.100.1/24"

echo "Adding tun device $DEV"
ip tuntap add dev $DEV mode tun && \
ip address add $IP_ADDRESS dev $DEV && \
ip link set $DEV up
