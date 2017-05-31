/*
 *	BIRD Client Bash Expansion
 *
 *	(c) 2017       Jan Moskyto Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nest/bird.h"
#include "client/client.h"

static int comp_type, comp_cword;
const char *comp_now, *comp_last;

void complete_init(int argc, char **argv) {
  /* In argv, there are:
   * $NOW
   * $COMP_TYPE
   * $COMP_CWORD
   * $COMP_POINT
   * ${COMP_WORDS[@]}
   */

  comp_now = argv[0];

  if (argc < COMPLETE_ARGC)
    die("Not enough args.");

  if (sscanf(argv[1], "%d", &comp_type) != 1)
    die("Strange COMP_TYPE=\"%s\".", argv[1]);

  if (sscanf(argv[2], "%d", &comp_cword) != 1)
    die("Strange COMP_CWORD=\"%s\".", argv[2]);

  if (comp_cword + COMPLETE_ARGC >= argc)
    die("COMP_CWORD=%d points after end of arg list.", comp_cword);

  comp_last = argv[COMPLETE_ARGC + comp_cword];
  return;
}

int do_complete(char *cmd) {
  if ((*cmd == 0) && (comp_type == 63))
    printf("-s\n-l\n-v\n-r\n");

  char buf[256];
  int res = cmd_complete(cmd, strlen(cmd), buf, 1);
  if (res == 1)
    printf("%s%s\n", comp_now, buf);

    
  return 0;
}

