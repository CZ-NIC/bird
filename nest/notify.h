/*
 *	BIRD Internet Routing Daemon -- Notificators and Listeners
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NOTIFY_H_
#define _BIRD_NOTIFY_H_

#include "lib/lists.h"

struct listener {
  node sender_node;
  node receiver_node;

  void (*hook)(struct listener *who, void *data);
  void (*dump)(struct listener *who);
  void (*unsub)(struct listener *who);
};

static inline void subscribe(struct listener *who, list *sender, list *receiver)
{
  ASSERT(!NODE_VALID(&(who->sender_node)));
  ASSERT(!NODE_VALID(&(who->receiver_node)));

  add_tail(sender, &(who->sender_node));
  add_tail(receiver, &(who->receiver_node));
}

static inline void unsubscribe(struct listener *who)
{
  /* Allow multiple unsubscribe */
  if (!NODE_VALID(&(who->sender_node))
      && !NODE_VALID(&(who->receiver_node)))
    return;

  ASSERT(NODE_VALID(&(who->sender_node))
      && NODE_VALID(&(who->receiver_node)));

  rem_node(&(who->sender_node));
  rem_node(&(who->receiver_node));

  who->sender_node = who->receiver_node = (node) {};
  CALL(who->unsub, who);
}

static inline void unsubscribe_all(list *receiver)
{
  struct listener *n;
  node *x, *y;
  WALK_LIST2_DELSAFE(n, x, y, *receiver, receiver_node)
    unsubscribe(n);
}

static inline void notify(list *sender, void *data)
{
  struct listener *n;
  node *x, *y;
  WALK_LIST2_DELSAFE(n, x, y, *sender, sender_node)
    n->hook(n, data);
}

static inline void listeners_dump(list *sender, list *receiver)
{
  ASSERT((!sender) || (!receiver));
  ASSERT(sender || receiver);

  struct listener *n;
  node *x;
  if (sender)
    WALK_LIST2(n, x, *sender, sender_node) {
      debug("\t\tNotifier: hook %p", n->hook);
      CALL(n->dump, n);
      debug("\n");
    }

  if (receiver)
    WALK_LIST2(n, x, *receiver, receiver_node) {
      debug("\t\tNotifier: hook %p", n->hook);
      CALL(n->dump, n);
      debug("\n");
    }
}


#endif
