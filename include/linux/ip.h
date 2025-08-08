#ifndef _LINUX_IP_H
#define _LINUX_IP_H

#include <linux/types.h>

/* Standard well-defined IP protocols */
#define IPPROTO_IP      0       /* Dummy protocol for TCP */
#define IPPROTO_ICMP    1       /* Internet Control Message Protocol */
#define IPPROTO_TCP     6       /* Transmission Control Protocol */
#define IPPROTO_UDP     17      /* User Datagram Protocol */

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
            version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
    /*The options start here. */
} __attribute__((packed));

#endif /* _LINUX_IP_H */