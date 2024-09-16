#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/io-loop.h"

#include "flock/flock.h"

#include <stdlib.h>

static void
container_mainloop(struct flock_machine_container_config *cfg, int fd)
{
  log(L_INFO "container mainloop");
  /* TODO cleanup the loops from the forked process */
  while (1)
  {
    pause();
    log(L_INFO "woken up!");
  }
}

struct container_start_callback {
  callback cb;
  sock *s, *skm;
  struct birdloop *loop;
  pool *pool;

  /* Stored socket hooks */
  int (*rx_hook)(sock *, uint size);
  void (*err_hook)(sock *, int);
  void *data;

  /* Actual config */
  struct flock_machine_container_config cfg;
};

static void
container_start_sk_err(sock *s, int e)
{
  struct container_start_callback *cb = s->data;

  cb->skm->data = NULL;
  s->data = cb->data;
  s->err_hook = cb->err_hook;

  mb_free(cb);
  s->err_hook(s, e);
}

static int
container_parent_rx(sock *skm, uint size)
{
  bug("container_parent_rx");
  ASSERT_DIE(size >= 3);

  ASSERT_DIE(skm->rbuf[0] == 0xa1);

  switch (skm->rbuf[1])
  {
    case 0:
      {
	pid_t pid;
	if (skm->rbuf[2] < 24)
	  pid = skm->rbuf[2];
	else if (skm->rbuf[2] == 24)
	  pid = skm->rbuf[3];
	else if (skm->rbuf[2] == 25)
	  pid = skm->rbuf[3] << 8 + skm->rbuf[4];
	else if (skm->rbuf[3] == 26)
	  pid = skm->rbuf[3] << 32 + skm->rbuf[4] << 24 + skm->rbuf[5] << 16 + skm->rbuf[6];
	else
	  bug("not implemented");

	log(L_INFO "Machine started with PID %d", pid);

	if (!skm->data)
	  return 1;

	struct container_start_callback *cb = skm->data;
	struct linpool *lp = lp_new(cb->s->pool);
	struct cbor_writer *cw = cbor_init(cb->s->tbuf, cb->s->tbsize, lp);
	cbor_open_block_with_length(cw, 1);
	cbor_add_int(cw, -1);
	cbor_add_string(cw, "OK");
	sk_send(cb->s, cw->pt);
	rfree(lp);

	cb->s->data = cb->data;
	cb->s->err_hook = cb->err_hook;
	sk_resume_rx(cb->s->loop, cb->s, cb->rx_hook);

	mb_free(cb);
	return 1;
      }

    default:
      bug("unimplemented");
  }

  return 1;
}

static void
container_parent_err(sock *s, int e)
{
  log(L_ERR "Container parent error hook not implemented: %d (%s)", e, strerror(e));
  sk_close(s);
}

static void
container_start_callback(struct callback *_cb)
{
  SKIP_BACK_DECLARE(struct container_start_callback, cb, cb, _cb);

  ASSERT_DIE(birdloop_inside(&main_birdloop));

  log(L_INFO "Requested to start a container, name %s, base %s, work %s",
      cb->cfg.cf.name, cb->cfg.basedir, cb->cfg.workdir);

  /* create socketpair before forking to do communication */
  int fds[2];
  int e = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  pid_t pid = fork();
  if (pid < 0)
    die("Failed to fork exposed: %m");

  if (!pid)
  {
    close(fds[0]);
    container_mainloop(&cb->cfg, fds[1]); /* this never returns */
    bug("container_mainloop has returned");
  }

  close(fds[1]);

  birdloop_enter(cb->loop);
  sock *skm = sk_new(cb->pool);
  skm->type = SK_MAGIC;
  skm->fd = fds[0];
  skm->rx_hook = container_parent_rx;
  skm->err_hook = container_parent_err;
  skm->data = cb;
  cb->skm = skm;

  if (sk_open(skm, cb->loop) < 0)
    bug("Container listener: sk_open failed");

  birdloop_leave(cb->loop);
}

void
container_start(struct birdsock *s, struct flock_machine_container_config *cfg)
{
  struct container_start_callback *cb = mb_alloc(s->pool, sizeof *cb);
  *cb = (struct container_start_callback) {
    .cb = callback_init(&cb->cb, container_start_callback, &main_birdloop),
    .s = s,
    .loop = s->loop,
    .pool = s->pool,
    .rx_hook = s->rx_hook,
    .err_hook = s->err_hook,
    .data = s->data,
    .cfg = *cfg,
  };

  sk_pause_rx(s->loop, s);
  s->err_hook = container_start_sk_err;
  s->data = cb;

  callback_activate(&cb->cb);
}
