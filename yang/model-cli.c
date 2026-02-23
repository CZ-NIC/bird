/*
 *	BIRD -- YANG-CBOR / CORECONF api -- CLI model
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"

#include "nest/protocol.h"
#include "conf/conf.h"

#include "yang/model-cli.h"
#include "lib/cbor.h"

extern pool *rt_table_pool;
extern pool *rta_pool;


void cbor_putmemsize(struct cbor_writer *w, u64 offset, struct resmem m)
{
  cbor_put_posint(w, offset);
  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, 1);
    cbor_put_posint(w, m.effective);
    cbor_put_posint(w, 2);
    cbor_put_posint(w, m.overhead);
  }
}

bool
yang_model_cli_rpc_call_show_memory(struct yang_session *se)
{
  struct {
    struct cbor_writer w;
    struct cbor_writer_stack_item si[6];
  } _w;

  struct {
    struct coap_tx_option hdr;
    char data[256];
  } payload;
  /* TODO: convert this all to coap_tx_header / extend / commit */

  struct cbor_writer *w = &_w.w;
  cbor_writer_init(w, 6, payload.hdr.data, 256);

  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, 60003);
    CBOR_PUT_MAP(w) {
      cbor_put_posint(w, 1);
      CBOR_PUT_MAP(w) {
	struct resmem total = rmemsize(&root_pool);

	cbor_putmemsize(w, 1, rmemsize(rta_pool));
	cbor_putmemsize(w, 4, rmemsize(config_pool));
	cbor_putmemsize(w, 12, rmemsize(proto_pool));
	cbor_putmemsize(w, 15, rmemsize(rt_table_pool));

#ifdef HAVE_MMAP
	/* Pages */
	cbor_put_posint(w, 7);
	CBOR_PUT_MAP(w) {
	  uint hot_pages = atomic_load_explicit(&pages_kept, memory_order_relaxed)
	    + atomic_load_explicit(&pages_kept_locally, memory_order_relaxed);
	  uint cold_pages_index = atomic_load_explicit(&pages_kept_cold_index, memory_order_relaxed);

	  u64 hot = page_size * (hot_pages + cold_pages_index);
	  total.overhead += hot;

	  cbor_put_posint(w, 3);
	  cbor_put_posint(w, hot);

	  uint cold_pages = atomic_load_explicit(&pages_kept_cold, memory_order_relaxed);
	  uint pages_total_loc = atomic_load_explicit(&pages_total, memory_order_relaxed);
	  uint pages_active = pages_total_loc - hot_pages - cold_pages_index - cold_pages;

	  cbor_put_posint(w, 1);
	  cbor_put_posint(w, page_size * pages_active);
	  cbor_put_posint(w, 2);
	  cbor_put_posint(w, page_size * cold_pages);
	  cbor_put_posint(w, 4);
	  cbor_put_posint(w, atomic_load_explicit(&alloc_locking_in_rcu, memory_order_relaxed));
	}
#endif

	cbor_putmemsize(w, 18, total);
      }
    }
  }

  ASSERT_DIE(cbor_writer_done(w) == 1);
  payload.hdr.len = w->data.pos - w->data.start;
  payload.hdr.type = 0;

  struct coap_tx_option *content_format = COAP_TX_OPTION_INT(
	COAP_OPT_CONTENT_FORMAT, (u8) 140);

  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CONTENT,
	content_format, &payload.hdr));

  return true;
}
