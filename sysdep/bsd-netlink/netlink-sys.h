/*
 *	Netlink FreeBSD-specific functions
 *
 *	(c) 2022 Alexander Chernikov <melifaro@FreeBSD.org>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NETLINK_SYS_H_
#define _BIRD_NETLINK_SYS_H_

#include <netlink/netlink.h>
#include <netlink/netlink_route.h>

#ifndef	AF_MPLS
#define	AF_MPLS	39
#endif

#ifndef	SO_RCVBUFFORCE
#define	SO_RCVBUFFORCE	SO_RCVBUF
#endif

static inline int
netlink_error_to_os(int error)
{
	return (error);
}

#endif
