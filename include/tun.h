#ifndef TUN_H_INCLUDED
#define TUN_H_INCLUDED

#include <stdbool.h>

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

// allocate a tun device and return its file descriptor
int TUN_Alloc(char *dev);
int TUN_Exists(char *dev);
int TUN_Set_Dev_IP_Addr(const char *dev, const char *ip);

#endif
