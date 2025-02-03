/*
 *	BIRD -- Bidirectional Forwarding Detection (BFD)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NBFD_H_
#define _BIRD_NBFD_H_

#include "lib/tlists.h"
#include "lib/resource.h"
#include "conf/conf.h"

struct bfd_session;

struct bfd_options {
  u32 min_rx_int;
  u32 min_tx_int;
  u32 idle_tx_int;
  u8 multiplier;
  PACKED enum bfd_opt_passive {
    BFD_OPT_PASSIVE_UNKNOWN = 0,
    BFD_OPT_PASSIVE,
    BFD_OPT_NOT_PASSIVE,
  } passive;
  u8 mode;
  u8 auth_type;				/* Authentication type (BFD_AUTH_*) */
  list *passwords;			/* Passwords for authentication */
};

#define TLIST_PREFIX bfd_request
#define TLIST_TYPE struct bfd_request
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL

/* Reference held by the requestor. Free to unrequest */
struct bfd_request_ref {
  resource r;
  struct bfd_request *req;
};

/* The actual request, allocated by BFD, freed after unrequesting
 * but assuring safe handling by the low-latency BFD routines. */
struct bfd_request {
  TLIST_DEFAULT_NODE;

  ip_addr addr;
  ip_addr local;
  struct iface *iface;
  struct iface *vrf;
  struct bfd_options opts;

  callback * _Atomic notify;

  struct bfd_session *_Atomic session;

  struct bfd_state_pair {
    struct bfd_state {
      u8 state;
      u8 diag;
    } loc, rem;
  } cur, old;

  bool down;
};

void bfd_request_get_state(struct bfd_request *req);

#include "lib/tlists.h"

#define BGP_BFD_GRACEFUL	2	/* BFD down triggers graceful restart */

#define BFD_STATE_ADMIN_DOWN	0
#define BFD_STATE_DOWN		1
#define BFD_STATE_INIT		2
#define BFD_STATE_UP		3


static inline struct bfd_options * bfd_new_options(void)
{ return cfg_allocz(sizeof(struct bfd_options)); }

#ifdef CONFIG_BFD

struct bfd_request_ref * bfd_request_session(pool *p, ip_addr addr, ip_addr local, struct iface *iface, struct iface *vrf, callback *notify, const struct bfd_options *opts);
void bfd_update_request(struct bfd_request_ref *req, const struct bfd_options *opts);
void bfd_request_update_state(struct bfd_request *req);

static inline void cf_check_bfd(int use UNUSED) { }

#else

static inline struct bfd_request_ref * bfd_request_session(pool *p UNUSED, ip_addr addr UNUSED, ip_addr local UNUSED, struct iface *iface UNUSED, struct iface *vrf UNUSED, callback *notify UNUSED, const struct bfd_options *opts UNUSED) { return NULL; }
static inline void bfd_update_request(struct bfd_request_ref *req UNUSED, const struct bfd_options *opts UNUSED) { };
static inline void bfd_request_update_state(struct bfd_request *req UNUSED) { bug("BFD not compiled in!"); }
static inline void cf_check_bfd(int use) { if (use) cf_error("BFD not available"); }

#endif /* CONFIG_BFD */



#endif /* _BIRD_NBFD_H_ */
