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
#include "lib/tlists.h"

#define LISTENER(stype) struct listener__##stype
#define LISTENER_DEF(stype) \
  TLIST_DEF(listener__##stype); \
LISTENER(stype) { \
  resource r; \
  TNODE(listener__##stype) n; \
  void *self; \
  void (*unsubscribe)(void *self); \
  void (*notify)(void *self, const stype *data); \
}; \
extern struct resclass LISTENER_CLASS(stype) 

#define LISTENERS(stype) TLIST(listener__##stype)

#define LISTENER_CLASS(stype) listener_class__##stype
#define LISTENER_CLASS_DEF(stype) static void listener_unsubscribe__##stype(resource *r) { \
  LISTENER(stype) *L = (LISTENER(stype) *) r; \
  TREM_NODE(listener__##stype, L->n); \
  CALL(L->unsubscribe, L->self); \
} \
struct resclass LISTENER_CLASS(stype) = { \
  .name = "Listener " #stype, \
  .size = sizeof(LISTENER(stype)), \
  .free = listener_unsubscribe__##stype, \
}

#define INIT_LISTENERS(stype, sender) INIT_TLIST(listener__##stype, sender)

#define SUBSCRIBE(stype, pool, sender, _self, _notify, _unsubscribe) ({ \
    LISTENER(stype) *L = ralloc(pool, &listener_class__##stype); \
    L->notify = _notify; \
    L->unsubscribe = _unsubscribe; \
    L->self = _self; \
    L->n.self = L; \
    TADD_TAIL(listener__##stype, sender, L->n); \
    L; \
    })

#define UNSUBSCRIBE(stype, listener) do { \
  LISTENER(stype) *L = listener; \
  L->unsubscribe = NULL; \
  rfree(L); \
} while (0)

#define UNNOTIFY(stype, sender) do { \
  WALK_TLIST_DELSAFE(listener__##stype, L, sender) \
    rfree(L->self); \
} while (0)

#define NOTIFY(stype, sender, data) do { \
  const stype *_d = data; \
  WALK_TLIST_DELSAFE(listener__##stype, L, sender) \
    L->self->notify(L->self->self, _d); \
} while (0)

#endif
