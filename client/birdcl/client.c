/*
 *	BIRD Client
 *
 *	(c) 1999--2004 Martin Mares <mj@ucw.cz>
 *      (c) 2013 Tomas Hlavacek <tomas.hlavacek@nic.cz>
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
#include <sys/ioctl.h>
#include <signal.h>
#include <ctype.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "client/client.h"
#include "sysdep/unix/unix.h"

#define INPUT_BUF_LEN 2048

static char *opt_list = "s:vr";
static int verbose;
static char *init_cmd;
static int once;

extern char *server_path;
extern int server_fd;

extern int cstate;
extern int num_lines, skip_input, interactive;

static int term_lns=25;
static int term_cls=80;
struct termios tty_save;

void
input_start_list(void)
{
	/* Empty in non-ncurses version. */
}

void
input_stop_list(void)
{
	/* Empty in non-ncurses version. */
}

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
	init_cmd = "restrict";
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

      if (init_cmd)
	usage();

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

static void
run_init_cmd(void)
{
  if (init_cmd)
    {
      /* First transition - client received hello from BIRD
         and there is waiting initial command */
      submit_server_command(init_cmd);
      init_cmd = NULL;
      return;
    }

  if (!init_cmd && once && (cstate == STATE_PROMPT))
    {
      /* Initial command is finished and we want to exit */
      cleanup();
      exit(0);
    }
}

/*** Input ***/

static void
got_line(char *cmd_buffer)
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
	  if (!handle_internal_command(cmd))
	    submit_server_command(cmd);

	  free(cmd);
	}
    }
  free(cmd_buffer);
}

void
cleanup(void)
{
  /* No ncurses -> restore terminal state. */
  if (interactive)
    if (tcsetattr (0, TCSANOW, &tty_save) != 0)
      {
        perror("tcsetattr error");
        exit(EXIT_FAILURE);
      }
}

static void
print_prompt(void)
{
  /* No ncurses -> no status to reveal/hide, print prompt manually. */
  printf("bird> ");
  fflush(stdout);
}


static int lastnb(char *str)
{
  int i;
  for (i=strlen(str)-1; i>0; i--)
    {
      if(!isblank(str[i]))
        return i;
    }

  return 0;
}

static void
term_read(void)
{
  char *buf = malloc(INPUT_BUF_LEN);

  if (fgets(buf, INPUT_BUF_LEN, stdin) == NULL) {
    free(buf);
    exit(0);
  }

  if (buf[strlen(buf)-1] != '\n')
    {
      printf("Input too long.\n");
      free(buf);
      return;
    }

  if (strlen(buf) <= 0)
    {
      free(buf);
      return;
    }

  buf[strlen(buf)-1] = '\0';

  if (!interactive)
    {
      print_prompt();
      printf("%s\n",buf);
    }

  if (buf[lastnb(buf)] == '?')
    {
      printf("\n");
      cmd_help(buf, strlen(buf));
      free(buf);
      return;
    }

  if (strlen(buf) > 0)
    {
      got_line(buf); /* buf is free()-ed inside */
    }
  else
    {
      free(buf); /* no command, only newline -> no-op */
      return;
    }

}

/*** Communication with server ***/

void
more(void)
{
  struct termios tty;

  printf("--More--\015");
  fflush(stdout);

  if (tcgetattr(0, &tty) != 0)
    {
      perror("tcgetattr error");
      exit(EXIT_FAILURE);
    }
  tty.c_lflag &= (~ECHO);
  tty.c_lflag &= (~ICANON);
  if (tcsetattr (0, TCSANOW, &tty) != 0)
    {
      perror("tcsetattr error");
      exit(EXIT_FAILURE);
    }

 redo:
  switch (getchar())
    {
    case 32:
      num_lines = 2;
      break;
    case 13:
      num_lines--;
      break;
    case '\n':
      num_lines--;
      break;
    case 'q':
      skip_input = 1;
      break;
    default:
      goto redo;
    }

  tty.c_lflag |= ECHO;
  tty.c_lflag |= ICANON;
  if (tcsetattr (0, TCSANOW, &tty) != 0)
    {
      perror("tcsetattr error");
      exit(EXIT_FAILURE);
    }

  printf("        \015");
  fflush(stdout);
}

static void
get_term_size(void)
{
  struct winsize tws;
  if (ioctl(0, TIOCGWINSZ, &tws) == 0)
    {
      term_lns = tws.ws_row;
      term_cls = tws.ws_col;
    }
  else
    {
       term_lns = 25;
       term_cls = 80;
    }
}

#define PRINTF(LEN, PARGS...) do { if (!skip_input) len = printf(PARGS); } while(0)

void
server_got_reply(char *x)
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
        cstate = STATE_PROMPT;
        skip_input = 0;
        return;
      }
    }
  else
    PRINTF(len, "??? <%s>\n", x);

  if (skip_input)
    return;

  if (interactive && (len > 0))
    {
      num_lines += (len + term_cls - 1) / term_cls; /* Divide and round up */
      if (num_lines >= term_lns)
        more();
    }
}

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
        {
          FD_SET(0, &select_fds);
          if (interactive)
            print_prompt();
        }

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
          run_init_cmd();
        }

      if (FD_ISSET(0, &select_fds))
        term_read();
    }
}

static void
sig_handler(int signal)
{
  cleanup();
  exit(0);
}

int
main(int argc, char **argv)
{
  interactive = isatty(fileno(stdin));
  if (interactive)
    {
      if (signal(SIGINT, sig_handler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
      if (signal(SIGHUP, sig_handler) == SIG_IGN)
        signal(SIGHUP, SIG_IGN);
      if (signal(SIGTERM, sig_handler) == SIG_IGN)
        signal(SIGTERM, SIG_IGN);

      get_term_size();

      if (tcgetattr(0, &tty_save) != 0)
        {
          perror("tcgetattr error");
          return(EXIT_FAILURE);
        }
    }

  parse_args(argc, argv);
  cmd_build_tree();
  server_connect();
  select_loop();
  return 0;
}
