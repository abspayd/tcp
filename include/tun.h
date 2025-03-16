#ifndef __TUN_H
#define __TUN_H

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

// allocate a tun device and return its file descriptor
int tun_alloc(char *dev);

#endif
