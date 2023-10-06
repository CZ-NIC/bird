/*
 *	BIRD -- UNIX Kernel Route Syncer
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_KRT_H_
#define _BIRD_KRT_H_

struct config;
struct krt_config;
struct krt_proto;
struct kif_config;
struct kif_proto;

#include "nest/iface.h"
#include "sysdep/config.h"
#include CONFIG_INCLUDE_KRTSYS_H

#define KRT_DEFAULT_ECMP_LIMIT	16

#define EA_KRT_SOURCE	EA_CODE(PROTOCOL_KERNEL, 0)
#define EA_KRT_METRIC	EA_CODE(PROTOCOL_KERNEL, 1)

#define KRT_REF_SEEN	0x1	/* Seen in table */
#define KRT_REF_BEST	0x2	/* Best in table */

#define KRT_LEARN_NONE	0	/* Do not learn */
#define KRT_LEARN_ALIEN	1	/* Learn KRT_SRC_ALIEN routes */
#define KRT_LEARN_ALL	2	/* Learn both KRT_SRC_ALIEN and KRT_SRC_KERNEL routes */

/* Whenever we recognize our own routes, we allow learing of foreign routes */

#ifdef CONFIG_SELF_CONSCIOUS
#define KRT_ALLOW_LEARN
#endif

/* krt.c */

extern struct protocol proto_unix_kernel;

struct krt_config {
  struct proto_config c;
  struct krt_params sys;	/* Sysdep params */
  btime scan_time;		/* How often we re-scan routes */
  int persist;			/* Keep routes when we exit */
  int learn;			/* Learn routes from other sources */
  int graceful_restart;		/* Regard graceful restart recovery */
  int merge_paths;		/* Exported routes are merged for ECMP */
};

struct krt_proto {
  struct proto p;
  struct krt_state sys;		/* Sysdep state */

#ifdef KRT_ALLOW_LEARN
  struct rtable *krt_table;	/* Internal table of inherited routes */
#endif

  timer *scan_timer;
  struct bmap sync_map;		/* Keeps track which exported routes were successfully written to kernel */
  struct bmap seen_map;		/* Routes seen during last periodic scan */
  node krt_node;		/* Node in krt_proto_list */
  byte af;			/* Kernel address family (AF_*) */
  byte ready;			/* Initial feed has been finished */
  byte initialized;		/* First scan has been finished */
  byte reload;			/* Next scan is doing reload */
};

extern pool *krt_pool;

#define KRT_CF ((struct krt_config *)p->p.cf)

#define KRT_TRACE(pr, fl, msg, args...) do {	\
  DBG("KRT: " msg "\n" , ## args);		\
  if (pr->p.debug & fl)				\
    { log(L_TRACE "%s: " msg, pr->p.name , ## args); } } while(0)

struct proto_config * kif_init_config(int class);
void kif_request_scan(void);
void krt_use_shared_scan(void);
void krt_got_route(struct krt_proto *p, struct rte *e, s8 src);
void krt_got_route_async(struct krt_proto *p, struct rte *e, int new, s8 src);

static inline int
krt_get_sync_error(struct krt_proto *p, struct rte *e)
{
  return (p->p.proto_state == PS_UP) &&
    bmap_test(&p->p.main_channel->export_map, e->id) &&
    !bmap_test(&p->sync_map, e->id);
}

/* Values for rte->u.krt_sync.src */
#define KRT_SRC_UNKNOWN	-1	/* Nobody knows */
#define KRT_SRC_BIRD	 0	/* Our route (not passed in async mode) */
#define KRT_SRC_REDIRECT 1	/* Redirect route, delete it */
#define KRT_SRC_ALIEN	 2	/* Route installed by someone else */
#define KRT_SRC_KERNEL	 3	/* Kernel routes, are ignored by krt syncer */

extern struct protocol proto_unix_iface;

struct kif_config {
  struct proto_config c;
  struct kif_params sys;	/* Sysdep params */

  list iface_list;		/* List of iface configs (struct kif_iface_config) */
  btime scan_time;		/* How often we re-scan interfaces */
};

struct kif_iface_config {
  struct iface_patt i;

  ip_addr pref_v4;
  ip_addr pref_v6;
  ip_addr pref_ll;
};

struct kif_proto {
  struct proto p;
  struct kif_state sys;		/* Sysdep state */
};

extern struct kif_proto *kif_proto;

#define KIF_CF ((struct kif_config *)p->p.cf)

struct kif_iface_config * kif_get_iface_config(struct iface *iface);
struct proto_config * krt_init_config(int class);


/* krt sysdep */

void krt_sys_io_init(void);
void krt_sys_init(struct krt_proto *);
int krt_sys_start(struct krt_proto *);
void krt_sys_shutdown(struct krt_proto *);
int krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o);

void krt_sys_preconfig(struct config *);
void krt_sys_postconfig(struct krt_config *);
void krt_sys_init_config(struct krt_config *);
void krt_sys_copy_config(struct krt_config *, struct krt_config *);

int  krt_capable(rte *e);
void krt_do_scan(struct krt_proto *);
void krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old);
int krt_sys_get_attr(const eattr *a, byte *buf, int buflen);


/* kif sysdep */

void kif_sys_init(struct kif_proto *);
void kif_sys_start(struct kif_proto *);
void kif_sys_shutdown(struct kif_proto *);
int kif_sys_reconfigure(struct kif_proto *, struct kif_config *, struct kif_config *);

void kif_sys_init_config(struct kif_config *);
void kif_sys_copy_config(struct kif_config *, struct kif_config *);

void kif_do_scan(struct kif_proto *);

int kif_update_sysdep_addr(struct iface *i);

#endif
