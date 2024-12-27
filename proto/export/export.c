/*
 *	BIRD -- Export Protocol
 *
 *	(c) 2024 Georgy A. Kirichenko <g-e-o-r-g-y@yandex-team.ru>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Export
 *
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"
#include "lib/net.h"
#include "lib/lists.h"

#include "proto/bgp/bgp.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib/socket.h"
#include <stdlib.h>

#include "sysdep/unix/unix.h"

#include "export.h"

static byte
buf_realloc(struct export_buf *buf, uint64_t size)
{
	size_t ofs = buf->tpos - buf->tbuf;
	if (ofs > size) {
		ofs = 0;
	}

	byte *new = realloc(buf->tbuf, size);
	if (new == NULL) {
		return 1;
	}

	buf->tbuf = new;
	buf->tpos = buf->tbuf + ofs;
	buf->size = size;

	return 0;
}

static char *
dump_attr_uint(char *wptr, const struct eattr *a)
{
	*(uint32_t *)wptr = a->id;
	wptr += 4;
	*(uint32_t *)wptr = a->u.data;
	wptr += 4;
	return wptr;
}

static char *
dump_attr_plain_data(char *wptr, const struct eattr *a)
{
	*(uint32_t *)wptr = a->id;
	wptr += 4;
	*(uint32_t *)wptr = a->u.ptr->length;
	wptr += 4;
	memcpy(wptr, a->u.ptr->data, a->u.ptr->length);
	wptr += a->u.ptr->length;
	return wptr;
}

static char *
dump_route_attrs(char *wptr, rte *route)
{
	char *attr_start = wptr;
	wptr += 4;
	struct ea_list *ea = route->attrs->eattrs;
	while (ea) {
		for (int idx = 0; idx < ea->count; ++idx) {
			struct eattr *a = ea->attrs + idx;
			if (EA_PROTO(a->id) != PROTOCOL_BGP)
				continue;
			switch (EA_ID(a->id)) {
			case BA_ORIGIN:
			case BA_LOCAL_PREF:
			case BA_MULTI_EXIT_DISC:
			case BA_ORIGINATOR_ID:
				wptr = dump_attr_uint(wptr, a);
				break;
			case BA_AS_PATH:
			case BA_NEXT_HOP:
			case BA_COMMUNITY:
			case BA_EXT_COMMUNITY:
			case BA_LARGE_COMMUNITY:
			case BA_MPLS_LABEL_STACK:
			case BA_CLUSTER_LIST:
				wptr = dump_attr_plain_data(wptr, a);
				break;
			}
		}
		ea = ea->next;
	}
	*(uint32_t *)attr_start = (uint32_t)(wptr - attr_start);
	return wptr;
}

static size_t
export_route_size(rte *route)
{
	size_t size = 4 + sizeof(net_addr_union) + 4;
	size += sizeof(ip_addr);

	size += 4;
	struct ea_list *ea = route->attrs->eattrs;
	while (ea) {
		for (int idx = 0; idx < ea->count; ++idx) {
			struct eattr *a = ea->attrs + idx;
			if (EA_PROTO(a->id) != PROTOCOL_BGP)
				continue;
			switch (EA_ID(a->id)) {
			case BA_ORIGIN:
			case BA_LOCAL_PREF:
			case BA_MULTI_EXIT_DISC:
			case BA_ORIGINATOR_ID:
				size += 4 + 4;
				break;
			case BA_AS_PATH:
			case BA_NEXT_HOP:
			case BA_COMMUNITY:
			case BA_EXT_COMMUNITY:
			case BA_LARGE_COMMUNITY:
			case BA_MPLS_LABEL_STACK:
			case BA_CLUSTER_LIST:
				size += 4 + 4 + a->u.ptr->length;
				break;
			}
		}
		ea = ea->next;
	}

	return size;
}

static void
export_rt_notify(struct proto *P, struct channel *src_ch UNUSED,
	struct network *n, rte *new, rte *old)
{
	struct proto_export *p = (struct proto_export *)P;

	if (p->p.disabled)
		return;

	sock *s = p->s;

	if (new == NULL && old == NULL)
		return;

	struct export_buf *write_buf = p->send_buf + p->send_buf_index;

	rte *route = new;
	uint32_t export_type = 1;
	if (!route) {
		route = old;
		export_type = 2;
	}

	ip_addr peer_addr = IPA_NONE;

	if (route->sender->proto != NULL &&
	    route->sender->proto->proto != NULL &&
	    route->sender->proto->proto->class == PROTOCOL_BGP) {
		struct bgp_proto *peer = (struct bgp_proto *)route->sender->proto;
		peer_addr = peer->remote_ip;
	}

	if (write_buf->tpos + export_route_size(route) > write_buf->tbuf + write_buf->size) {
		struct export_buf *sock_buf = p->send_buf + (1 - p->send_buf_index);
		if (sock_buf->tbuf == sock_buf->tpos) {
			s->tbuf = write_buf->tbuf;
			s->tpos = write_buf->tpos;
			s->ttx = write_buf->tbuf;
			p->send_buf_index = 1 - p->send_buf_index;
			write_buf = sock_buf;
		} else {
			if (buf_realloc(write_buf, write_buf->size * 2))
				return;
		}
	}

	byte *wptr = write_buf->tpos;
	wptr += 4;

	*(net_addr_union *)wptr = *(net_addr_union *)n->n.addr;
	wptr += sizeof(net_addr_union);

	*(uint32_t *)wptr = export_type;
	wptr += 4;

	*(ip_addr *)wptr = peer_addr;
	wptr += sizeof(ip_addr);

	wptr = dump_route_attrs(wptr, route);

	*(uint32_t *)write_buf->tpos = wptr - write_buf->tpos;
	write_buf->tpos = wptr;

	struct export_buf *sock_buf = p->send_buf + (1 - p->send_buf_index);
	if (sock_buf->tbuf == sock_buf->tpos) {
		s->tbuf = write_buf->tbuf;
		s->tpos = write_buf->tpos;
		s->ttx = write_buf->tbuf;
		p->send_buf_index = 1 - p->send_buf_index;
	}
}

/* Initiate refeed on export's request */
static void
export_reload_routes(struct channel *C)
{
	/* Route reload on one channel is just refeed on the other */
	channel_request_feeding(C);
}

static void
export_postconfig(struct proto_config *CF)
{
	struct export_config *cf = (struct export_config *) CF;
	struct channel_config *cc = proto_cf_main_channel(CF);

	if (!cc->table)
		cf_error("Primary routing table not specified");

	if (cc->rx_limit.action)
		cf_error("Export protocol does not support receive limits");

	if (cc->in_keep_filtered)
		cf_error("Export protocol prohibits keeping filtered routes");

	cc->debug = cf->c.debug;
}

static int
export_configure_channels(struct proto_export *p, struct export_config *cf)
{
	struct channel_config *cc;

	WALK_LIST(cc, cf->c.channels) {
		struct channel_config cfg = {
			.name = cc->table->name,
			.channel = cc->channel,
			.table = cc->table,
			.out_filter = cc->out_filter,
			.out_limit = cc->out_limit,
			.ra_mode = RA_ANY,
			.debug = cc->debug,
			.rpki_reload = cc->rpki_reload,
		};
		struct channel *ch = NULL;
		int res = proto_configure_channel(&p->p, &ch, &cfg);
		if (res == 0) {
			cf_error("Could not configure channel");
			return 0;
		}
	}
	return 1;
}

static int
export_rx(sock *s UNUSED, uint size UNUSED) {
	return 1;
}

static void
export_tx(sock *s) {
	struct proto_export *p = (struct proto_export *)s->data;
	struct export_buf *sock_buf = p->send_buf + (1 - p->send_buf_index);
	sock_buf->tpos = sock_buf->tbuf;

	struct export_buf *write_buf = p->send_buf + p->send_buf_index;
	s->tbuf = write_buf->tbuf;
	s->tpos = write_buf->tpos;
	s->ttx = write_buf->tbuf;
	p->send_buf_index = 1 - p->send_buf_index;
}

static void
export_err(sock *s, int err UNUSED) {
	struct proto_export *p = (struct proto_export *)s->data;

	if (!p->p.disabled) {
		s->tpos = s->ttx = s->tbuf;

		config_add_obstacle(p->p.cf->global);

		rem_node(&p->p.cf->n);
		p->p.cf_new = NULL;
		p->p.reconfiguring = 1;
		proto_notify_state(&p->p, PS_DOWN);
	}
}

static int
export_connect(sock *s, uint size UNUSED)
{
	struct proto_export *p = (struct proto_export *)s->data;

	s->rx_hook = export_rx;
	s->tx_hook = export_tx;
	s->err_hook = export_err;

	struct symbol *sym;

	new_config = config;
	cfg_mem = config->mem;
	config->current_scope = config->root_scope;
	sym = cf_default_name(new_config, "export-child %u", &(p->child_index));
	proto_clone_config(sym, p->p.cf);
	new_config = NULL;
	cfg_mem = NULL;

	struct proto_export *cp = (struct proto_export *) proto_spawn(sym->proto, 0);
	cp->s = s;
	s->data = cp;
	rmove(s, cp->p.pool);
	cp->send_buf[0].tbuf = NULL;
	cp->send_buf[0].tpos = NULL;
	cp->send_buf[0].size = 0;
	buf_realloc(cp->send_buf + 0, 4096 * 1024);
	cp->send_buf[1].tbuf = NULL;
	cp->send_buf[1].tpos = NULL;
	cp->send_buf[1].size = 0;
	cp->send_buf_index = 0;
	buf_realloc(cp->send_buf + 1, 4096 * 1024);

	return 1;
}

static void
export_cleanup(struct proto *P)
{
	struct proto_export *p = (struct proto_export *) P;
	struct export_config *cf = p->cf;

	if (cf->c.parent != NULL) {
		xfree(p->send_buf[0].tbuf);
		xfree(p->send_buf[1].tbuf);

	} else {
		unlink(cf->socket);
	}
}

static struct proto *
export_init(struct proto_config *CF)
{

	struct proto *P = proto_new(CF);
	struct proto_export *p = (struct proto_export *) P;
	struct export_config *cf = (struct export_config *) CF;

	p->cf = cf;

	if (CF->parent != NULL) {
		P->rt_notify = export_rt_notify;
		P->reload_routes = export_reload_routes;
		export_configure_channels(p, cf);
	} else {
		unlink(cf->socket);

		sock *s = sk_new(p->p.pool);
		s->type = SK_UNIX_PASSIVE;
		s->rx_hook = export_connect;
		s->rbsize = 1024;
		s->tbsize = 1024;
		s->fast_rx = 1;
		s->data = p;
		p->s = s;
		if (sk_open_unix(s, cf->socket) < 0)
			cf_error("Cannot create export socket %s", cf->socket);
	}

	return (P);
}

static int
export_reconfigure(struct proto *P, struct proto_config *CF)
{
	struct proto_export *p = (struct proto_export *) P;
	struct export_config *cf = p->cf;

	struct export_config *new_cf = (struct export_config *) CF;

	if (CF->parent != NULL) {
		struct channel_config *cc;
		WALK_LIST(cc, new_cf->c.channels) {
			byte found = 0;

			struct channel *c;
			WALK_LIST(c, p->p.channels) {
				if (!strcmp(cc->table->name, c->table->name)) {
					found = 1;
					break;
				}
			}
			if (!found)
				return 0;
		}

		struct channel *c;
		WALK_LIST(c, p->p.channels) {
			byte found = 0;

			struct channel_config *cc;
			WALK_LIST(cc, new_cf->c.channels) {
				if (!strcmp(cc->table->name, c->table->name)) {
					found = 1;
					break;
				}
			}
			if (!found)
				return 0;
		}
	} else {
		if (strcmp(cf->socket, new_cf->socket)) {
			unlink(cf->socket);
			rfree(p->s);

			sock *s = sk_new(p->p.pool);
			s->type = SK_UNIX_PASSIVE;
			s->rx_hook = export_connect;
			s->rbsize = 1024;
			s->tbsize = 1024;
			s->fast_rx = 1;
			s->data = p;
			p->s = s;
			if (sk_open_unix(s, new_cf->socket) < 0)
				cf_error("Cannot create export socket %s", cf->socket);
		}
	}

	p->cf = new_cf;

	return 1;
}

static void
export_copy_config(struct proto_config *dest UNUSED,
		  struct proto_config *src UNUSED)
{
	/* Just a shallow copy, not many items here */
}

static void
export_get_status(struct proto *P UNUSED, byte *buf)
{
	bsprintf(buf, "%s", "feeding");
}

static void
export_show_stats(struct channel *ch)
{
	struct proto_stats *s1 = &ch->stats;
	cli_msg(-1006, "  Routes:         %u exported", s1->exp_routes);
	cli_msg(-1006, "  Updates:        %u received", s1->exp_updates_received);
	cli_msg(-1006, "  Updates:        %u rejected", s1->exp_updates_rejected);
	cli_msg(-1006, "  Updates:        %u filtered", s1->exp_updates_filtered);
	cli_msg(-1006, "  Updates:        %u accepted", s1->exp_updates_accepted);
	cli_msg(-1006, "  Withdraws:      %u received", s1->exp_withdraws_received);
	cli_msg(-1006, "  Withdraws:      %u accepted", s1->exp_withdraws_accepted);

}

static const char *export_feed_state[] = {
	[ES_DOWN] = "down", [ES_FEEDING] = "feed", [ES_READY] = "up" };

static void
export_show_proto_info(struct proto *P)
{
	struct proto_export *p = (struct proto_export *) P;

	struct channel *ch;
	WALK_LIST(ch, p->p.channels) {

		cli_msg(-1006, "  Channel %s", ch->name);
		cli_msg(-1006, "    Table:          %s", ch->table->name);
		cli_msg(-1006, "    Export state:   %s",
		    export_feed_state[ch->export_state]);
		cli_msg(-1006, "    Export filter:  %s",
		    filter_name(ch->out_filter));

		if (P->proto_state != PS_DOWN)
			export_show_stats(ch);
	}
}

void
export_update_debug(struct proto *P)
{
	struct proto_export *p = (struct proto_export *) P;

	struct channel *ch;
	WALK_LIST(ch, p->p.channels) {
		ch->debug = p->p.debug;
	}
}

static int
export_start(struct proto *P)
{
  proto_notify_state(P, PS_UP);

  return PS_UP;
}

static int
export_shutdown(struct proto *P UNUSED)
{
	return PS_DOWN;
}


struct protocol proto_export = {
	.name =			"Export",
	.template =		"export%d",
	.class =		PROTOCOL_EXPORT,
	.proto_size =		sizeof(struct proto_export),
	.config_size =		sizeof(struct export_config),
	.postconfig =		export_postconfig,
	.init =			export_init,
	.cleanup =		export_cleanup,
	.reconfigure =		export_reconfigure,
	.copy_config =		export_copy_config,
	.get_status =		export_get_status,
	.show_proto_info =	export_show_proto_info,
	.start =		export_start,
	.shutdown =		export_shutdown,
};

void
export_build(void)
{
	proto_build(&proto_export);
}
