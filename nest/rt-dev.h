/*
 *	BIRD -- Direct Device Routes
 *
 *	(c) 1998--1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RT_DEV_H_
#define _BIRD_RT_DEV_H_

struct rt_dev_config {
  struct proto_config c;
  list iface_list;		/* list of struct iface_patt */
  int check_link;

  struct channel_config *ip4_channel;
  struct channel_config *ip6_channel;
};

struct rt_dev_proto {
  struct proto p;
  struct channel *ip4_channel;
  struct channel *ip6_channel;
};

#endif
