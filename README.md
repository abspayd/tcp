# tcp

An experimental handmade TCP/IP stack written in C.

## Installation

**Prerequisites:** Linux, gcc

```
git clone https://github.com/abspayd/tcp.git
cd tcp
make
```

## Features

Implemented so far:

 - Berkely socket API
 - Berkely socket API
 - FNV-1A hash for TCB table
 - Checksum
 - Simple ICMP ping implementation
 - TCP 3-way handshake connection establishment
 - Read/write to a TUN network interface


## Future

Plans for the future:

 - Support for all stages of the TCP connection life-cycle
 - Data segmentation
 - Congestion control
 - Timeouts and retransmission

## References

 - https://www.ietf.org/rfc/rfc9293.html
 - https://www.rfc-editor.org/info/rfc791/
 - https://en.wikipedia.org/wiki/IPv4
 - https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 - http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a

