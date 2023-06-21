/*
 *	BIRD -- Table-to-Table Routing Protocol a.k.a Pipe
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PIPE_H_
#define _BIRD_PIPE_H_

struct merging_import {
  uint limit;
  uint use_aggregator;
};

struct merging_export {
  uint limit;
  uint use_aggregator;
};

struct pipe_config {
  struct proto_config c;
  struct rtable_config *peer;		    /* Table we're connected to */
  struct merging_import config_import;  /* From peer table to primary table */
  struct merging_export config_export;  /* From primary table to peer table */
};

struct pipe_proto {
  struct proto p;
  struct channel *pri;
  struct channel *sec;
};

#endif
