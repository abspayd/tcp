#ifndef __IP_H
#define __IP_H

#include <netinet/ip.h>
#include <stdint.h>
#include <unistd.h>

int get_ip_header(const char *buf, size_t buf_len, struct iphdr **ip_header);
uint16_t ip_checksum(struct iphdr *ip_header, char *options, size_t options_len);

#endif
