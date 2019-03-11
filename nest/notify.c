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

LISTENER_DECL(void);

static void
listener_unsubscribe(resource *r)
{
  LISTENER(void) *L = (LISTENER(void) *) r;
  rem_node(&(L->n));
  CALL(L->unsubscribe, L->self);
}

struct resclass listener_class = {
  .name = "Listener",
  .size = sizeof(LISTENER(void)),
  .free = listener_unsubscribe,
  .dump = NULL,
  .lookup = NULL,
  .memsize = NULL,
};
