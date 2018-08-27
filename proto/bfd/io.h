/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BFD_IO_H_
#define _BIRD_BFD_IO_H_

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"


void ev2_schedule(event *e);

void sk_start(sock *s);
void sk_stop(sock *s);

struct birdloop *birdloop_new(void);
void birdloop_start(struct birdloop *loop);
void birdloop_stop(struct birdloop *loop);
void birdloop_free(struct birdloop *loop);

void birdloop_enter(struct birdloop *loop);
void birdloop_leave(struct birdloop *loop);
void birdloop_mask_wakeups(struct birdloop *loop);
void birdloop_unmask_wakeups(struct birdloop *loop);


#endif /* _BIRD_BFD_IO_H_ */
