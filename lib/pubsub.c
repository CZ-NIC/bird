/*
 *	BIRD Library -- Publish/Subscribe Queue
 *
 *	(c) 2025 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2025 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Publish/Subscribe Queues
 *
 * BIRD implements a publish/subscribe messaging system with dynamic topic
 * management and resource tracking. The system allows multiple publishers to
 * send messages to named topics, which are then distributed to all subscribers
 * of those topics.
 *
 * The system is built around four main components: queues, topics, publishers,
 * and subscribers. A &ps_queue serves as the central coordination point,
 * maintaining list of topics. Topics are created dynamically when first
 * referenced and can have multiple publishers and subscribers attached.
 *
 * Publishers and subscribers are implemented as managed resources. Each
 * publisher or subscriber can be attached to only one topic. When publishers or
 * subscribers are destroyed, they automatically detach from their associated
 * topics.
 *
 * The ps_init_queue() function initializes a new message queue with a given
 * name and memory pool. Topics are created on-demand through ps_get_topic().
 * Publishers attach to topics using ps_attach() and can send messages via
 * ps_publish(), which sends notification to all subscribers. Subscribers use
 * ps_subscribe() to register for topic updates. When a subscriber joins
 * a topic with attached publishers, these publishers are notified of the new
 * subscription through their subscribe hooks.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"

#include "lib/event.h"
#include "lib/resource.h"
#include "lib/pubsub.h"

static void ps_publisher_free(resource *r);
static void ps_publisher_dump(struct dump_request *dreq, resource *r);
static void ps_subscriber_free(resource *r);
static void ps_subscriber_dump(struct dump_request *dreq, resource *r);
static void ps_event_loop(void *ptr);


static struct resclass ps_publisher_class = {
  .name = "Publisher",
  .size = sizeof(ps_publisher),
  .free = ps_publisher_free,
  .dump = ps_publisher_dump,
};

static struct resclass ps_subscriber_class = {
  .name = "Subscriber",
  .size = sizeof(ps_subscriber),
  .free = ps_subscriber_free,
  .dump = ps_subscriber_dump,
};


void
ps_init_queue(ps_queue *q, pool *p, const char *name)
{
  q->name = name;
  q->pool = rp_new(p, name);
  q->event = ev_new_init(q->pool, ps_event_loop, q);
  init_list(&q->topics);
  init_list(&q->topics_pending);
}

ps_topic *
ps_get_topic(ps_queue *q, const char *name)
{
  ps_topic *t;

  WALK_LIST(t, q->topics)
    if (!strcmp(t->name, name))
      return t;

  WALK_LIST(t, q->topics_pending)
    if (!strcmp(t->name, name))
      return t;

  t = mb_allocz(q->pool, sizeof(struct ps_topic));
  strncpy(t->name, name, sizeof(t->name)-1);

  init_list(&t->publishers);
  init_list(&t->subscribers);
  add_tail(&q->topics, &t->n);

  DBG("%s: New topic '%s', total %u\n",
      q->name, t->name, list_length(&q->topics) + list_length(&q->topics_pending));

  return t;
}

ps_publisher *
ps_publisher_new(pool *p, void (*subscribe_hook)(struct ps_publisher *), void *data)
{
  ps_publisher *pub = ralloc(p, &ps_publisher_class);
  pub->subscribe_hook = subscribe_hook;
  pub->data = data;
  return pub;
}

static void
ps_publisher_free(resource *r)
{
  ps_publisher *pub = (void *) r;

  if (pub->topic)
    ps_detach(pub);
}

static void
ps_publisher_dump(struct dump_request *dreq, resource *r)
{
  ps_publisher *pub = (void *) r;

  RDUMP("(queue %p, topic '%s')", pub->queue, pub->topic ? pub->topic->name : "NULL");
  RDUMP("(subscribe_hook %p, data %p)", pub->subscribe_hook, pub->data);
}

void
ps_attach(ps_publisher *pub, ps_queue *q, ps_topic *t)
{
  ASSERT(!pub->queue && !pub->topic);

  pub->queue = q;
  pub->topic = t;
  add_tail(&t->publishers, &pub->n);

  DBG("%s: Publisher %p added to topic '%s', total %u\n",
      q->name, pub, t->name, list_length(&t->publishers));
}

void
ps_detach(ps_publisher *pub)
{
  ASSERT(pub->queue && pub->topic);
  ps_queue *q UNUSED = pub->queue;
  ps_topic *t UNUSED = pub->topic;

  pub->queue = NULL;
  pub->topic = NULL;
  rem_node(&pub->n);

  DBG("%s: Publisher %p removed from topic '%s', total %u\n",
      q->name, pub, t->name, list_length(&t->publishers));
}

void
ps_publish(ps_publisher *pub, void *msg, uint length)
{
  ASSERT(pub->queue && pub->topic);
  ps_topic *t = pub->topic;

  DBG("%s: Message from publisher %p on topic '%s', notifying %u subscribers\n",
      pub->queue->name, pub, t->name, list_length(&t->subscribers));

  /* Ping subscribers */
  ps_subscriber *sub; node *n;
  WALK_LIST2(sub, n, t->subscribers, n)
    sub->notify_hook(sub, msg, length);
}


ps_subscriber *
ps_subscriber_new(pool *p, void (*notify_hook)(struct ps_subscriber *, void *, uint), void *data)
{
  ps_subscriber *sub = ralloc(p, &ps_subscriber_class);
  sub->notify_hook = notify_hook;
  sub->data = data;
  return sub;
}

static void
ps_subscriber_free(resource *r)
{
  ps_subscriber *sub = (void *) r;

  if (sub->topic)
    ps_unsubscribe(sub);
}

static void
ps_subscriber_dump(struct dump_request *dreq, resource *r)
{
  ps_subscriber *sub = (void *) r;

  RDUMP("(queue %p, topic '%s')", sub->queue, sub->topic ? sub->topic->name : "NULL");
  RDUMP("(notify_hook %p, data %p)", sub->notify_hook, sub->data);
}

void
ps_subscribe(ps_subscriber *sub, ps_queue *q, ps_topic *t)
{
  ASSERT(!sub->queue && !sub->topic);

  sub->queue = q;
  sub->topic = t;
  add_tail(&t->subscribers, &sub->n);

  DBG("%s: Subscriber %p added to topic '%s', total %u\n",
      q->name, sub, t->name, list_length(&t->subscribers));

  if (EMPTY_LIST(t->publishers))
    return;

  /* Ping publishers */
  rem_node(&t->n);
  add_tail(&q->topics_pending, &t->n);

  if (!ev_active(q->event))
    ev_schedule(q->event);
}

void
ps_unsubscribe(ps_subscriber *sub)
{
  ASSERT(sub->queue && sub->topic);
  ps_queue *q UNUSED = sub->queue;
  ps_topic *t UNUSED = sub->topic;

  sub->queue = NULL;
  sub->topic = NULL;
  rem_node(&sub->n);

  DBG("%s: Subscriber %p removed from topic '%s', total %u\n",
      q->name, sub, t->name, list_length(&t->subscribers));
}

static void
ps_event_loop(void *ptr)
{
  ps_queue *q = ptr;

  ps_topic *t;
  WALK_LIST_FIRST(t, q->topics_pending)
  {
    DBG("%s: Subscription change on topic '%s', notifying %u publishers\n",
	q->name, t->name, list_length(&t->publishers));

    rem_node(&t->n);
    add_tail(&q->topics, &t->n);

    struct ps_publisher *pub; node *n;
    WALK_LIST2(pub, n, t->publishers, n)
      CALL(pub->subscribe_hook, pub);
  }
}
