#ifndef _ASM_BYTEORDER_H
#define _ASM_BYTEORDER_H

/* For x86 we're always little endian */
#define __LITTLE_ENDIAN_BITFIELD

/* Basic type definitions */
typedef __u16 __be16; /* big endian 16-bit */
typedef __u32 __be32; /* big endian 32-bit */
typedef __u16 __sum16; /* checksum */

/* Byte swapping */
#define __swab16(x) ((__u16)(             \
    (((__u16)(x) & (__u16)0x00ffU) << 8) | \
    (((__u16)(x) & (__u16)0xff00U) >> 8)))

#define __swab32(x) ((__u32)(             \
    (((__u32)(x) & (__u32)0x000000ffUL) << 24) | \
    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) | \
    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) | \
    (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

/* Network byte order is big endian */
#define __cpu_to_be16(x) __swab16((x))
#define __cpu_to_be32(x) __swab32((x))
#define __be16_to_cpu(x) __swab16((x))
#define __be32_to_cpu(x) __swab32((x))

#define htons(x) __cpu_to_be16(x)
#define ntohs(x) __be16_to_cpu(x)
#define htonl(x) __cpu_to_be32(x)
#define ntohl(x) __be32_to_cpu(x)

#endif /* _ASM_BYTEORDER_H */