#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/io-loop.h"

#include "flock/flock.h"

#include <stdlib.h>

void
container_start(struct birdsock *s, struct flock_machine_container_config *cfg)
{
  log(L_INFO "Requested to start a container, name %s, base %s, work %s",
      cfg->cf.name, cfg->basedir, cfg->workdir);

  struct linpool *lp = lp_new(s->pool);
  struct cbor_writer *cw = cbor_init(s->tbuf, s->tbsize, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -1);
  cbor_add_string(cw, "OK");
  sk_send(s, cw->pt);
  rfree(lp);
}
