/*
 *	BIRD Internet Routing Daemon -- Notificators and Listeners
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/resource.h"
#include "nest/notify.h"

struct listener {
  resource r;
  node n;

  void (*notify)(void *self, const void *data);
  void (*unsubscribe)(void *self);

  void *self;
};

static void
listener_unsubscribe(resource *r)
{
  struct listener *L = (struct listener *) r;
  rem_node(&(L->n));
  CALL(L->unsubscribe, L->self);
}

static struct resclass listener_class = {
  .name = "Listener",
  .size = sizeof(struct listener),
  .free = listener_unsubscribe,
  .dump = NULL,
  .lookup = NULL,
  .memsize = NULL,
};

struct listener *
subscribe(pool *p, list *sender, void (*notify)(void *, const void *), void (*unsubscribe)(void *), void *self)
{
  struct listener *L = ralloc(p, &listener_class);
  L->notify = notify;
  L->unsubscribe = unsubscribe;
  L->self = self;

  add_tail(sender, &(L->n));
  return L;
}

void unsubscribe(struct listener *L)
{
  L->unsubscribe = NULL;
  rfree(L);
}

void unsubscribe_all(list *sender)
{
  struct listener *L;
  node *x, *y;
  WALK_LIST2_DELSAFE(L, x, y, *sender, n)
    rfree(L);
}

void notify(list *sender, const void *data)
{
  struct listener *L;
  node *x, *y;
  WALK_LIST2_DELSAFE(L, x, y, *sender, n)
    L->notify(L->self, data);
}
