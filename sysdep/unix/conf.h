/*
 *	BIRD -- Unix Port Config Structures
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_UNIX_CONFIG_H_
#define _BIRD_UNIX_CONFIG_H_

#include "lib/tlists.h"

#define TLIST_PREFIX control_socket_config
#define TLIST_TYPE struct control_socket_config
#define TLIST_ITEM n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL

struct control_socket_config {
  TLIST_DEFAULT_NODE;
  struct config *config;
  struct control_socket *cs;

  ip_addr addr;
  uint port;

  const char *unix;
  uid_t uid;
  gid_t gid;
  u8 restricted;
};

#include "lib/tlists.h"

struct log_config {
  node n;
  uint mask;				/* Classes to log */
  void *fh;				/* FILE to log to, NULL=syslog */
  struct rfile *rf;			/* Resource for log file */
  const char *filename;			/* Log filename */
  const char *backup;			/* Secondary filename (for log rotation) */
  off_t pos;				/* Position/size of current log */
  off_t limit;				/* Log size limit */
  int terminal_flag;
};

#endif
