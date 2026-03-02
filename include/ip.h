#ifndef __IP_H
#define __IP_H

#include <netinet/ip.h>
#include <stdint.h>
#include <unistd.h>

extern int IP_Get_Header(const char *buf, size_t buf_len, struct iphdr **ip_header);
extern uint16_t IP_Checksum(struct iphdr *ip_header, char *options, size_t options_len);
extern struct iphdr IP_Header_Create(in_addr_t source_ipaddr, in_addr_t dest_ipaddr);
extern void IP_Debug(struct iphdr *ip_header);

#endif
