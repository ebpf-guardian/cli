#ifndef _LINUX_IF_ETHER_H
#define _LINUX_IF_ETHER_H

#include <linux/types.h>

/* IEEE 802.3 Ethernet magic constants */
#define ETH_ALEN        6       /* Octets in one ethernet addr */
#define ETH_HLEN        14      /* Total octets in header */
#define ETH_ZLEN        60      /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500    /* Max. octets in payload */
#define ETH_FRAME_LEN   1514    /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN     4       /* Octets in the FCS */

#define ETH_P_IP        0x0800  /* Internet Protocol packet */
#define ETH_P_ARP       0x0806  /* Address Resolution packet */
#define ETH_P_IPV6      0x86DD  /* IPv6 over bluebook */

/* Ethernet header */
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];     /* destination eth addr */
    unsigned char   h_source[ETH_ALEN];   /* source eth addr */
    __be16          h_proto;              /* packet type ID field */
} __attribute__((packed));

/* Allow single-byte access to the protocol field. */
#define __constant_htons(x) ((__be16)((__u16)(x)))

#endif /* _LINUX_IF_ETHER_H */