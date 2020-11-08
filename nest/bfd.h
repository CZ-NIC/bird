/*
 *	BIRD -- Bidirectional Forwarding Detection (BFD)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NBFD_H_
#define _BIRD_NBFD_H_

#include "lib/lists.h"
#include "lib/resource.h"
#include "conf/conf.h"

struct bfd_session;

struct bfd_options {
  u32 min_rx_int;
  u32 min_tx_int;
  u32 idle_tx_int;
  u8 multiplier;
  u8 passive;
  u8 passive_set;
  u8 mode;
};

struct bfd_request {
  resource r;
  node n;

  ip_addr addr;
  ip_addr local;
  struct iface *iface;
  struct iface *vrf;
  struct bfd_options opts;

  void (*hook)(struct bfd_request *);
  void *data;

  struct bfd_session *session;

  u8 state;
  u8 diag;
  u8 old_state;
  u8 down;
};

#define BGP_BFD_GRACEFUL	2	/* BFD down triggers graceful restart */

#define BFD_STATE_ADMIN_DOWN	0
#define BFD_STATE_DOWN		1
#define BFD_STATE_INIT		2
#define BFD_STATE_UP		3


static inline struct bfd_options * bfd_new_options(void)
{ return cfg_allocz(sizeof(struct bfd_options)); }

#ifdef CONFIG_BFD

struct bfd_request * bfd_request_session(pool *p, ip_addr addr, ip_addr local, struct iface *iface, struct iface *vrf, void (*hook)(struct bfd_request *), void *data, const struct bfd_options *opts);
void bfd_update_request(struct bfd_request *req, const struct bfd_options *opts);

static inline void cf_check_bfd(int use UNUSED) { }

#else

static inline struct bfd_request * bfd_request_session(pool *p UNUSED, ip_addr addr UNUSED, ip_addr local UNUSED, struct iface *iface UNUSED, struct iface *vrf UNUSED, void (*hook)(struct bfd_request *) UNUSED, void *data UNUSED, const struct bfd_options *opts UNUSED) { return NULL; }
static inline void bfd_update_request(struct bfd_request *req UNUSED, const struct bfd_options *opts UNUSED) { };

static inline void cf_check_bfd(int use) { if (use) cf_error("BFD not available"); }

#endif /* CONFIG_BFD */



#endif /* _BIRD_NBFD_H_ */
