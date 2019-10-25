/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *		  2017 Jan Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "lib/idm.h"
#include "nest/protocol.h"
#include "nest/route.h"

#define P(a,b) ((a<<8) | b)

const char *
filter_name(const struct filter *filter)
{
  if (!filter)
    return "ACCEPT";
  else if (filter == FILTER_REJECT)
    return "REJECT";
  else if (!filter->sym)
    return "(unnamed)";
  else
    return filter->sym->name;
}

struct filter *f_new_where(struct f_inst *where)
{
  struct f_inst *cond = f_new_inst(FI_CONDITION, where,
				   f_new_inst(FI_DIE, F_ACCEPT),
				   f_new_inst(FI_DIE, F_REJECT));

  struct filter *f = cfg_allocz(sizeof(struct filter));
  f->root = f_linearize(cond);
  return f;
}

#define CA_KEY(n)	n->name, n->fda.type
#define CA_NEXT(n)	n->next
#define CA_EQ(na,ta,nb,tb)	(!strcmp(na,nb) && (ta == tb))
#define CA_FN(n,t)	(mem_hash(n, strlen(n)) ^ (t*0xaae99453U))
#define CA_ORDER	8 /* Fixed */

struct ca_storage {
  struct ca_storage *next;
  struct f_dynamic_attr fda;
  u32 uc;
  char name[0];
};

HASH(struct ca_storage) ca_hash;

static struct idm ca_idm;
static struct ca_storage **ca_storage;
static uint ca_storage_max;

static void
ca_free(resource *r)
{
  struct custom_attribute *ca = (void *) r;
  struct ca_storage *cas = HASH_FIND(ca_hash, CA, ca->name, ca->fda->type);
  ASSERT(cas);

  ca->name = NULL;
  ca->fda = NULL;
  if (!--cas->uc) {
    uint id = EA_CUSTOM_ID(cas->fda.ea_code);
    idm_free(&ca_idm, id);
    HASH_REMOVE(ca_hash, CA, cas);
    ca_storage[id] = NULL;
    mb_free(cas);
  }
}

static void
ca_dump(resource *r)
{
  struct custom_attribute *ca = (void *) r;
  debug("name \"%s\" id 0x%04x ea_type 0x%02x f_type 0x%02x\n",
      ca->name, ca->fda->ea_code, ca->fda->type, ca->fda->f_type);
}

static struct resclass ca_class = {
  .name = "Custom attribute",
  .size = sizeof(struct custom_attribute),
  .free = ca_free,
  .dump = ca_dump,
  .lookup = NULL,
  .memsize = NULL,
};

struct custom_attribute *
ca_lookup(pool *p, const char *name, int f_type)
{
  int ea_type;

  switch (f_type) {
    case T_INT:
      ea_type = EAF_TYPE_INT;
      break;
    case T_IP:
      ea_type = EAF_TYPE_IP_ADDRESS;
      break;
    case T_QUAD:
      ea_type = EAF_TYPE_ROUTER_ID;
      break;
    case T_PATH:
      ea_type = EAF_TYPE_AS_PATH;
      break;
    case T_CLIST:
      ea_type = EAF_TYPE_INT_SET;
      break;
    case T_ECLIST:
      ea_type = EAF_TYPE_EC_SET;
      break;
    case T_LCLIST:
      ea_type = EAF_TYPE_LC_SET;
      break;
    default:
      cf_error("Custom route attribute of unsupported type");
  }

  static int inited = 0;
  if (!inited) {
    idm_init(&ca_idm, &root_pool, 8);
    HASH_INIT(ca_hash, &root_pool, CA_ORDER);

    ca_storage_max = 256;
    ca_storage = mb_allocz(&root_pool, sizeof(struct ca_storage *) * ca_storage_max);

    inited++;
  }

  struct ca_storage *cas = HASH_FIND(ca_hash, CA, name, ea_type);
  if (cas) {
    cas->uc++;
  } else {

    uint id = idm_alloc(&ca_idm);

    if (id >= EA_CUSTOM_BIT)
      cf_error("Too many custom attributes.");

    if (id >= ca_storage_max) {
      ca_storage_max *= 2;
      ca_storage = mb_realloc(ca_storage, sizeof(struct ca_storage *) * ca_storage_max * 2);
    }

    cas = mb_allocz(&root_pool, sizeof(struct ca_storage) + strlen(name) + 1);
    cas->fda = f_new_dynamic_attr(ea_type, f_type, EA_CUSTOM(id));
    cas->uc = 1;

    strcpy(cas->name, name);
    ca_storage[id] = cas;

    HASH_INSERT(ca_hash, CA, cas);
  }

  struct custom_attribute *ca = ralloc(p, &ca_class);
  ca->fda = &(cas->fda);
  ca->name = cas->name;
  return ca;
}

const char *
ea_custom_name(uint ea)
{
  uint id = EA_CUSTOM_ID(ea);
  if (id >= ca_storage_max)
    return NULL;

  if (!ca_storage[id])
    return NULL;

  return ca_storage[id]->name;
}

