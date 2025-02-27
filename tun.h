#ifndef __TUN_H
#define __TUN_H

#include <unistd.h>

// allocate a tun device and return its file descriptor
int tun_alloc(char *dev);

// packet debug dumps
void dump_ip(unsigned char *buf, size_t buf_len);
void dump_tcp(unsigned char *buf, size_t buf_len);
void dump_packet(unsigned char *buf, size_t buf_len);

#endif
