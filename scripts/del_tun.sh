#!/bin/bash
if [[ -z $1 ]]; then
    echo "$0 DEV"
    exit 1;
fi

DEV=$1

echo "Removing tun device $DEV"
ip tuntap del dev $DEV mode tun
