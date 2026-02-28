#ifndef TUN_H_INCLUDED
#define TUN_H_INCLUDED

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

// allocate a tun device and return its file descriptor
int tun_alloc(char *dev);
int set_dev_ip_addr(const char *dev, const char *ip);

#endif
