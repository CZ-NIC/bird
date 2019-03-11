/*
 *	BIRD Internet Routing Daemon -- Notificators and Listeners
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NOTIFY_H_
#define _BIRD_NOTIFY_H_

#include "lib/resource.h"
#include "lib/lists.h"

#define LISTENER(stype) struct listener__##stype
#define LISTENER_DECL(stype) LISTENER(stype) { \
  resource r; \
  node n; \
  void *self; \
  void (*unsubscribe)(void *self); \
  void (*notify)(void *self, const stype *data); \
};

extern struct resclass listener_class;

#define SUBSCRIBE(stype, pool, sender, _self, _notify, _unsubscribe) ({ \
    LISTENER(stype) *L = ralloc(pool, &listener_class); \
    L->notify = _notify; \
    L->unsubscribe = _unsubscribe; \
    L->self = _self; \
    add_tail(&(sender), &(L->n)); \
    L; \
    })

#define UNSUBSCRIBE(stype, listener) do { \
  LISTENER(stype) *L = listener; \
  L->unsubscribe = NULL; \
  rfree(L); \
} while (0)

#define UNNOTIFY(stype, sender) do { \
  LISTENER(stype) *L; \
  node *x, *y; \
  WALK_LIST2_DELSAFE(L, x, y, sender, n) \
    rfree(L); \
} while (0)

#define NOTIFY(stype, sender, data) do { \
  const stype *_d = data; \
  LISTENER(stype) *L; \
  node *x, *y; \
  WALK_LIST2_DELSAFE(L, x, y, sender, n) \
    L->notify(L->self, _d); \
} while (0)

#endif
