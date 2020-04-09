/*
 *	Filters: dereferencing metaobjects
 *
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#define PARSER 1

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"
#include "conf/conf.h"
#include "conf/cf-parse.tab.h"

static struct f_val deref_proto__name__deref(struct f_val *val)
{ return (struct f_val) { .type = T_STRING, .val.s = val->val.proto->name }; }

static const struct f_deref deref_proto__name = {
  .deref = deref_proto__name__deref,
  .name = "name",
  .source_type = T_PROTO,
  .result_type = T_STRING,
};

static struct f_val deref_channel__name__deref(struct f_val *val)
{ return (struct f_val) { .type = T_STRING, .val.s = val->val.channel->name }; }

static const struct f_deref deref_channel__name = {
  .deref = deref_channel__name__deref,
  .name = "name",
  .source_type = T_CHANNEL,
  .result_type = T_STRING,
};

static struct f_val deref_channel__proto__deref(struct f_val *val)
{ return (struct f_val) { .type = T_PROTO, .val.proto = val->val.channel->proto }; }

static const struct f_deref deref_channel__proto = {
  .deref = deref_channel__proto__deref,
  .name = "proto",
  .source_type = T_CHANNEL,
  .result_type = T_PROTO,
};

const struct f_deref *f_get_deref(enum f_type type, const struct keyword *kw)
{
  if (!type)
    cf_error("Can't dereference an object with unsure type");

#define CX(t, v)  ((u64) (t) | ((v) << (8 * sizeof (enum f_type))))
  switch (CX(type, kw->value))
  {
    case CX(T_PROTO, NAME):
      return &deref_proto__name;
    case CX(T_CHANNEL, NAME):
      return &deref_channel__name;
    case CX(T_CHANNEL, PROTO):
      return &deref_channel__proto;
  }

  cf_error("Can't call (%s).%s: Undefined operation", f_type_name(type), kw->name);
}
