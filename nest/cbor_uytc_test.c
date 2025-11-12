#include "nest/bird.h"
#include "lib/resource.h"
#include "cbor_uytc_test.h"
#include "nest/cbor.h"
#include "nest/cbor_shortcuts.h"

pool *uytc_test_pool;

/*
 * CBOR diagnostic notation:
 *
 * {
 *   "show_status:message": {
 *     "version": "2.17.1+branch.yang.57c25d5e6ee2",
 *     "body": {
 *       "router_id":  1051197441, // 62.
 *       "hostname": "localhost",
 *       "server_time": "2025-06-16 10:24:45.224",
 *       "last_reboot": "2025-06-15 10:00:00.000",
 *       "last_reconfiguration": "2025-06-15 12:34:56.000",
 *     }
 *     "state": "up and running",
 *   }
 * }
 */
byte show_status_static_names[] = {
  0xa1,
    // show_status:message
    0x73, 's', 'h', 'o', 'w', '_', 's', 't', 'a', 't', 'u', 's', ':', 'm', 'e', 's', 's', 'a', 'g', 'e',
    0xa3,
      // version
      0x67, 'v', 'e', 'r', 's', 'i', 'o', 'n',
      // 2.17.1+branch.yang.57c25d5e6ee2
      0x78, 0x1f, '2', '.', '1', '7', '.', '1', '+', 'b', 'r', 'a', 'n', 'c', 'h', '.', 'y', 'a', 'n', 'g', '.', '5', '7', 'c', '2', '5', 'd', '5', 'e', '6', 'e', 'e', '2',

      // body
      0x64, 'b', 'o', 'd', 'y',
      0xa5,
	// router_id
	0x69, 'r', 'o', 'u', 't', 'e', 'r', '_', 'i', 'd',
	// 62.168.0.1 as 1051197441
	0x1a, 0x3e, 0xa8, 0x00, 0x01,

	// hostname
	0x68, 'h', 'o', 's', 't', 'n', 'a', 'm', 'e',
	0x69, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',

	// server_time
	0x6b, 's', 'e', 'r', 'v', 'e', 'r', '_', 't', 'i', 'm', 'e',
	// 2025-06-16 10:24:45.224
	0x77, '2', '0', '2', '5', '-', '0', '6', '-', '1', '6', ' ', '1', '0', ':', '2', '4', ':', '4', '5', '.', '2', '2', '4',

	// last_reboot
	0x6b, 'l', 'a', 's', 't', '_', 'r', 'e', 'b', 'o', 'o', 't',
	// 2025-06-15 10:00:00.000
	0x77, '2', '0', '2', '5', '-', '0', '6', '-', '1', '5', ' ', '1', '0', ':', '0', '0', ':', '0', '0', '.', '0', '0', '0',

	// last_reconfiguration
	0x74, 'l', 'a', 's', 't', '_', 'r', 'e', 'c', 'o', 'n', 'f', 'i', 'g', 'u', 'r', 'a', 't', 'i', 'o', 'n',
	// 2025-06-15 12:34:56.000
	0x77, '2', '0', '2', '5', '-', '0', '6', '-', '1', '5', ' ', '1', '2', ':', '3', '4', ':', '5', '6', '.', '0', '0', '0',

	// !IGNORE gr_restart for now

      // state
      0x65, 's', 't', 'a', 't', 'e',
      // up and running
      0x6e, 'u', 'p', ' ', 'a', 'n', 'd', ' ', 'r', 'u', 'n', 'n', 'i', 'n', 'g',
};

/*
 * CBOR diagnostic notation:
 *
 * {
 *   "show_status:message": {
 *     "version: "",
 *     "body": {
 *       "router_id": "",
 *       "hostname": "",
 *       "server_time": "",
 *       "last_reboot",
 *       "last_reconfiguration": "",
 *     }
 *     "state": "",
 *   }
 * }
 */
byte show_status_statis_sids[] UNUSED = {
  0x00,
    0x00,
    0x00
};

void
uytc_test_init(void)
{
  uytc_test_pool = rp_new(&root_pool, "UYTC TEST");
}

static void
cleanup(struct uytc_test *conn)
{
  /* closes the socket */
  rfree(conn->s);
  rfree(conn->event);
  mb_free(conn);
}

static uint
generate_test_msg(byte *buffer, uint size)
{
  //byte *buff_start = buffer;
  if (size < sizeof(show_status_static_names)) {
    return 0;
  }
  memcpy(buffer, show_status_static_names, sizeof(show_status_static_names));
  return sizeof(show_status_static_names);
}

static void
uytc_test_event(void *data)
{
  struct uytc_test *conn = data;

  if (conn->to_write == 0)
  {
    #define SIZE 2048
    conn->buffer = mb_alloc(uytc_test_pool, SIZE);
    conn->to_write = generate_test_msg(conn->buffer, conn->s->tbsize);
    conn->s->tbuf = conn->buffer;

    if (conn->to_write == 0)
    {
      cleanup(conn);
      return;
    }

    ev_schedule(conn->event);
    return;
  }
  else if (conn->written < conn->to_write)
  {
    int res = sk_send(conn->s, conn->to_write - conn->written);
    if (res != 0) // both error and success
    {
      cleanup(conn);
      return;
    }

    ev_schedule(conn->event);
  }
  else
  {
    cleanup(conn);
    return;
  }
}

static int
uytc_test_sock_rx(sock *s UNUSED, uint read UNUSED)
{
  /* ignore */
  return 1; // all done
}

static void
uytc_test_sock_tx(sock *s UNUSED)
{
  struct uytc_test *conn = s->data;
  if (conn->written < conn->to_write)
    ev_schedule(conn->event);
  else
    cleanup(conn);
}

static void
uytc_test_sock_err(sock *s, int err UNUSED)
{
  struct uytc_test *conn = s->data;
  cleanup(conn);
}

void
handle_uytc_test_conn(sock *s UNUSED, uint size UNUSED)
{
  struct uytc_test *conn = mb_alloc(uytc_test_pool, sizeof(struct uytc_test));
  bzero(conn, sizeof(struct uytc_test));
  conn->event = ev_new(uytc_test_pool);
  conn->event->hook = uytc_test_event;
  conn->event->data = conn;
  conn->s = s;
  s->rx_hook = uytc_test_sock_rx;
  s->tx_hook = uytc_test_sock_tx;
  s->err_hook = uytc_test_sock_err;
  s->data = conn;

  ev_schedule(conn->event);
}

