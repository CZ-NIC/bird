/*
 *	BIRD Client
 *
 *	(c) 1999--2004 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <curses.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "client/client.h"
#include "sysdep/unix/unix.h"

static char *opt_list = "s:vr";
static int verbose;
static char *init_cmd;
static int once;
static int restricted;

extern char *server_path;
extern int server_fd;
extern byte server_read_buf[SERVER_READ_BUF_LEN];
extern byte *server_read_pos;

extern int input_initialized;
extern int input_hidden_end;
extern int cstate;
extern int nstate;

extern int num_lines, skip_input, interactive;

/*** Parsing of arguments ***/

static void
usage(void)
{
  fprintf(stderr, "Usage: birdc [-s <control-socket>] [-v] [-r]\n");
  exit(1);
}

static void
parse_args(int argc, char **argv)
{
  int c;

  while ((c = getopt(argc, argv, opt_list)) >= 0)
    switch (c)
      {
      case 's':
	server_path = optarg;
	break;
      case 'v':
	verbose++;
	break;
      case 'r':
	restricted = 1;
	break;
      default:
	usage();
      }

  /* If some arguments are not options, we take it as commands */
  if (optind < argc)
    {
      char *tmp;
      int i;
      int len = 0;

      for (i = optind; i < argc; i++)
	len += strlen(argv[i]) + 1;

      tmp = init_cmd = malloc(len);
      for (i = optind; i < argc; i++)
	{
	  strcpy(tmp, argv[i]);
	  tmp += strlen(tmp);
	  *tmp++ = ' ';
	}
      tmp[-1] = 0;

      once = 1;
    }
}

/*** Input ***/

/* HACK: libreadline internals we need to access */
extern int _rl_vis_botlin;
extern void _rl_move_vert(int);
extern Function *rl_last_func;

static void
add_history_dedup(char *cmd)
{
  /* Add history line if it differs from the last one */
  HIST_ENTRY *he = history_get(history_length);
  if (!he || strcmp(he->line, cmd))
    add_history(cmd);
}

void got_line(char *cmd_buffer)
{
  char *cmd;

  if (!cmd_buffer)
    {
      cleanup();
      exit(0);
    }
  if (cmd_buffer[0])
    {
      cmd = cmd_expand(cmd_buffer);
      if (cmd)
       {
         add_history_dedup(cmd);

         if (!handle_internal_command(cmd))
           submit_server_command(cmd);

         free(cmd);
       }
      else
       add_history_dedup(cmd_buffer);
    }
  free(cmd_buffer);
}

void
input_start_list(void)			/* Leave the currently edited line and make space for listing */
{
  _rl_move_vert(_rl_vis_botlin);
#ifdef HAVE_RL_CRLF
  rl_crlf();
#endif
}

void
input_stop_list(void)			/* Reprint the currently edited line after listing */
{
  rl_on_new_line();
  rl_redisplay();
}

static int
input_complete(int arg UNUSED, int key UNUSED)
{
  static int complete_flag;
  char buf[256];

  if (rl_last_func != input_complete)
    complete_flag = 0;
  switch (cmd_complete(rl_line_buffer, rl_point, buf, complete_flag))
    {
    case 0:
      complete_flag = 1;
      break;
    case 1:
      rl_insert_text(buf);
      break;
    default:
      complete_flag = 1;
#ifdef HAVE_RL_DING
      rl_ding();
#endif
    }
  return 0;
}

static int
input_help(int arg, int key UNUSED)
{
  int i, in_string, in_bracket;

  if (arg != 1)
    return rl_insert(arg, '?');

  in_string = in_bracket = 0;
  for (i = 0; i < rl_point; i++)
    {
   
      if (rl_line_buffer[i] == '"')
	in_string = ! in_string;
      else if (! in_string)
        {
	  if (rl_line_buffer[i] == '[')
	    in_bracket++;
	  else if (rl_line_buffer[i] == ']')
	    in_bracket--;
        }
    }

  /* `?' inside string or path -> insert */
  if (in_string || in_bracket)
    return rl_insert(1, '?');

  rl_begin_undo_group();		/* HACK: We want to display `?' at point position */
  rl_insert_text("?");
  rl_redisplay();
  rl_end_undo_group();
  input_start_list();
  cmd_help(rl_line_buffer, rl_point);
  rl_undo_command(1, 0);
  input_stop_list();
  return 0;
}

static void
input_init(void)
{
  rl_readline_name = "birdc";
  rl_add_defun("bird-complete", input_complete, '\t');
  rl_add_defun("bird-help", input_help, '?');
  rl_callback_handler_install("bird> ", got_line);
  input_initialized = 1;
//  readline library does strange things when stdin is nonblocking.
//  if (fcntl(0, F_SETFL, O_NONBLOCK) < 0)
//    die("fcntl: %m");
}

static void
input_hide(void)
{
  input_hidden_end = rl_end;
  rl_end = 0;
  rl_expand_prompt("");
  rl_redisplay();
}

static void
input_reveal(void)
{
  /* need this, otherwise some lib seems to eat pending output when
     the prompt is displayed */
  fflush(stdout);
  tcdrain(fileno(stdout));

  rl_end = input_hidden_end;
  rl_expand_prompt("bird> ");
  rl_forced_update_display();
}

void
update_state(void)
{
  if (nstate == cstate)
    return;

  if (restricted)
    {
       submit_server_command("restrict");
       restricted = 0;
       return;
    }

  if (init_cmd)
    {
      /* First transition - client received hello from BIRD
	 and there is waiting initial command */
      submit_server_command(init_cmd);
      init_cmd = NULL;
      return;
    }

  if (!init_cmd && once)
    {
      /* Initial command is finished and we want to exit */
      cleanup();
      exit(0);
    }

  if (nstate == STATE_PROMPT)
    {
      if (input_initialized)
	input_reveal();
      else
	input_init();
    }

  if (nstate != STATE_PROMPT)
    input_hide();

  cstate = nstate;
}

void
more(void)
{
  printf("--More--\015");
  fflush(stdout);

 redo:
  switch (getchar())
    {
    case 32:
      num_lines = 2;
      break;
    case 13:
      num_lines--;
      break;
    case 'q':
      skip_input = 1;
      break;
    default:
      goto redo;
    }

  printf("        \015");
  fflush(stdout);
}

void cleanup(void)
{
  if (input_initialized)
    {
      input_initialized = 0;
      input_hide();
      rl_callback_handler_remove();
    }
}


/*** Communication with server ***/

static fd_set select_fds;

static void
select_loop(void)
{
  int rv;
  while (1)
    {
      FD_ZERO(&select_fds);

      if (cstate != STATE_CMD_USER)
	FD_SET(server_fd, &select_fds);
      if (cstate != STATE_CMD_SERVER)
	FD_SET(0, &select_fds);

      rv = select(server_fd+1, &select_fds, NULL, NULL, NULL);
      if (rv < 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    die("select: %m");
	}

      if (FD_ISSET(server_fd, &select_fds))
	{
	  server_read();
	  update_state();
	}

      if (FD_ISSET(0, &select_fds))
	{
	  rl_callback_read_char();
	  update_state();
	}
    }
}

#define PRINTF(LEN, PARGS...) do { if (!skip_input) len = printf(PARGS); } while(0)

void server_got_reply(char *x)
{
  int code;
  int len = 0;

  if (*x == '+')                        /* Async reply */
    PRINTF(len, ">>> %s\n", x+1);
  else if (x[0] == ' ')                 /* Continuation */
    PRINTF(len, "%s%s\n", verbose ? "     " : "", x+1);
  else if (strlen(x) > 4 &&
           sscanf(x, "%d", &code) == 1 && code >= 0 && code < 10000 &&
           (x[4] == ' ' || x[4] == '-'))
    {
      if (code)
        PRINTF(len, "%s\n", verbose ? x : x+5);
      if (x[4] == ' ')
      {
        nstate = STATE_PROMPT;
        skip_input = 0;
        return;
      }
    }
  else
    PRINTF(len, "??? <%s>\n", x);

  if (skip_input)
    return;

  if (interactive && input_initialized && (len > 0))
    {
      int lns = LINES ? LINES : 25;
      int cls = COLS ? COLS : 80;
      num_lines += (len + cls - 1) / cls; /* Divide and round up */
      if ((num_lines >= lns)  && (cstate == STATE_CMD_SERVER))
        more();
    }
}

int
main(int argc, char **argv)
{
#ifdef HAVE_LIBDMALLOC
  if (!getenv("DMALLOC_OPTIONS"))
    dmalloc_debug(0x2f03d00);
#endif

  interactive = isatty(0);
  parse_args(argc, argv);
  cmd_build_tree();
  server_connect();
  select_loop();
  return 0;
}
