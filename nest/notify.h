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

struct listener;

struct listener *subscribe(pool *p, list *sender, void (*notify)(void *self, const void *data), void (*unsubscribe)(void *self), void *self);
void unsubscribe(struct listener *L);
void unsubscribe_all(list *sender);
void notify(list *sender, const void *data);

#endif
