/*
 *	BIRD Library -- Publish/Subscribe Queue
 *
 *	(c) 2025 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2025 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PUBSUB_H_
#define _BIRD_PUBSUB_H_

#include "lib/event.h"
#include "lib/lists.h"
#include "lib/resource.h"

typedef struct ps_queue
{
  const char *name;
  pool *pool;
  event *event;
  list topics;
  list topics_pending;
} ps_queue;

typedef struct ps_topic
{
  node n;
  char name[16];
  list publishers;
  list subscribers;
} ps_topic;

typedef struct ps_publisher
{
  resource r;
  node n;
  void (*subscribe_hook)(struct ps_publisher *);
  void *data;
  struct ps_queue *queue;
  struct ps_topic *topic;
} ps_publisher;

typedef struct ps_subscriber
{
  resource r;
  node n;
  void (*notify_hook)(struct ps_subscriber *, void *, uint);
  void *data;
  struct ps_queue *queue;
  struct ps_topic *topic;
} ps_subscriber;


void ps_init_queue(ps_queue *q, pool *p, const char *name);
ps_topic *ps_get_topic(ps_queue *q, const char *name);

ps_publisher *ps_publisher_new(pool *p, void (*subscribe_hook)(struct ps_publisher *), void *data);
void ps_attach(ps_publisher *pub, ps_queue *q, ps_topic *t);
void ps_detach(ps_publisher *pub);
void ps_publish(ps_publisher *pub, void *msg, uint length);

static inline void ps_attach_topic(ps_publisher *pub, ps_queue *q, const char *name)
{ ps_attach(pub, q, ps_get_topic(q, name)); }

ps_subscriber * ps_subscriber_new(pool *p, void (*notify_hook)(struct ps_subscriber *, void *, uint), void *data);
void ps_subscribe(ps_subscriber *sub, ps_queue *q, ps_topic *t);
void ps_unsubscribe(ps_subscriber *sub);

static inline void ps_subscribe_topic(ps_subscriber *sub, ps_queue *q, const char *name)
{ ps_subscribe(sub, q, ps_get_topic(q, name)); }

#endif
