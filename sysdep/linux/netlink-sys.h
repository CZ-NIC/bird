/*
 *	BIRD -- Linux Netlink Interface
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NETLINK_SYS_H_
#define _BIRD_NETLINK_SYS_H_

#include <asm/types.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifdef HAVE_MPLS_KERNEL
#include <linux/lwtunnel.h>
#endif

#ifndef MSG_TRUNC			/* Hack: Several versions of glibc miss this one :( */
#define MSG_TRUNC 0x20
#endif

#ifndef IFA_FLAGS
#define IFA_FLAGS 8
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

#ifndef RTA_TABLE
#define RTA_TABLE  15
#endif

#ifndef RTA_VIA
#define RTA_VIA	 18
#endif

#ifndef RTA_NEWDST
#define RTA_NEWDST  19
#endif

#ifndef RTA_ENCAP_TYPE
#define RTA_ENCAP_TYPE	21
#endif

#ifndef RTA_ENCAP
#define RTA_ENCAP  22
#endif

#ifndef NETLINK_GET_STRICT_CHK
#define NETLINK_GET_STRICT_CHK 12
#endif

static inline int
netlink_error_to_os(int error)
{
	return -error;
}

#endif
