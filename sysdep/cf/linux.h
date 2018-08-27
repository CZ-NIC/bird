/*
 *	Configuration for Linux based systems
 *
 *	(c) 1998--1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#define CONFIG_AUTO_ROUTES
#define CONFIG_SELF_CONSCIOUS
#define CONFIG_MULTIPLE_TABLES
#define CONFIG_ALL_TABLES_AT_ONCE
#define CONFIG_IP6_SADR_KERNEL

#define CONFIG_MC_PROPER_SRC
#define CONFIG_UNIX_DONTROUTE

#define CONFIG_INCLUDE_SYSIO_H "sysdep/linux/sysio.h"
#define CONFIG_INCLUDE_KRTSYS_H "sysdep/linux/krt-sys.h"

#define CONFIG_RESTRICTED_PRIVILEGES
#define CONFIG_INCLUDE_SYSPRIV_H "sysdep/linux/syspriv.h"


#ifndef AF_MPLS
#define AF_MPLS 28
#endif

/*
Link: sysdep/linux
Link: sysdep/unix
 */
