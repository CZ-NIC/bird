/*
 *	Configuration for FreeBSD based systems with netlink support
 *
 *	(c) 2022 Alexander Chernikov <melifaro@FreeBSD.org>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#define CONFIG_AUTO_ROUTES
#define CONFIG_SELF_CONSCIOUS
#define CONFIG_MULTIPLE_TABLES
#define CONFIG_SINGLE_ROUTE

#define CONFIG_SKIP_MC_BIND
#define CONFIG_NO_IFACE_BIND
#define CONFIG_USE_HDRINCL

#define CONFIG_INCLUDE_SYSIO_H "sysdep/bsd/sysio.h"
#define CONFIG_INCLUDE_KRTSYS_H "sysdep/linux/krt-sys.h"
#define CONFIG_INCLUDE_NLSYS_H "sysdep/bsd-netlink/netlink-sys.h"

/*
Link: sysdep/unix
Link: sysdep/bsd-netlink
 */
