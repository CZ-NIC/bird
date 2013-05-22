/*
 *	BIRD Client
 *
 *	(c) 1999--2004 Martin Mares <mj@ucw.cz>
 *	(c) 2013 Tomas Hlavacek <tmshlvck@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "client/client.h"
#include "sysdep/unix/unix.h"

char *server_path = PATH_CONTROL_SOCKET;
int server_fd;
byte server_read_buf[SERVER_READ_BUF_LEN];
byte *server_read_pos = server_read_buf;

int input_initialized;
int input_hidden_end;
int cstate = STATE_CMD_SERVER;
int nstate = STATE_CMD_SERVER;

int num_lines, skip_input, interactive;


/*** Input ***/

int
handle_internal_command(char *cmd)
{
  if (!strncmp(cmd, "exit", 4) || !strncmp(cmd, "quit", 4))
    {
      cleanup();
      exit(0);
    }
  if (!strncmp(cmd, "help", 4))
    {
      puts("Press `?' for context sensitive help.");
      return 1;
    }
  return 0;
}

void
submit_server_command(char *cmd)
{
  server_send(cmd);
  nstate = STATE_CMD_SERVER;
  num_lines = 2;
}

/*** Communication with server ***/

void
server_connect(void)
{
  struct sockaddr_un sa;

  server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0)
    die("Cannot create socket: %m");

  if (strlen(server_path) >= sizeof(sa.sun_path))
    die("server_connect: path too long");

  bzero(&sa, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, server_path);
  if (connect(server_fd, (struct sockaddr *) &sa, SUN_LEN(&sa)) < 0)
    die("Unable to connect to server control socket (%s): %m", server_path);
  if (fcntl(server_fd, F_SETFL, O_NONBLOCK) < 0)
    die("fcntl: %m");
}

void
server_read(void)
{
  int c;
  byte *start, *p;

 redo:
  c = read(server_fd, server_read_pos, server_read_buf + sizeof(server_read_buf) - server_read_pos);
  if (!c)
    die("Connection closed by server.");
  if (c < 0)
    {
      if (errno == EINTR)
	goto redo;
      else
	die("Server read error: %m");
    }

  start = server_read_buf;
  p = server_read_pos;
  server_read_pos += c;
  while (p < server_read_pos)
    if (*p++ == '\n')
      {
	p[-1] = 0;
	server_got_reply(start);
	start = p;
      }
  if (start != server_read_buf)
    {
      int l = server_read_pos - start;
      memmove(server_read_buf, start, l);
      server_read_pos = server_read_buf + l;
    }
  else if (server_read_pos == server_read_buf + sizeof(server_read_buf))
    {
      strcpy(server_read_buf, "?<too-long>");
      server_read_pos = server_read_buf + 11;
    }
}

void
wait_for_write(int fd)
{
  while (1)
    {
      int rv;
      fd_set set;
      FD_ZERO(&set);
      FD_SET(fd, &set);

      rv = select(fd+1, NULL, &set, NULL, NULL);
      if (rv < 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    die("select: %m");
	}

      if (FD_ISSET(server_fd, &set))
	return;
    }
}

void
server_send(char *cmd)
{
  int l = strlen(cmd);
  byte *z = alloca(l + 1);

  memcpy(z, cmd, l);
  z[l++] = '\n';
  while (l)
    {
      int cnt = write(server_fd, z, l);

      if (cnt < 0)
	{
	  if (errno == EAGAIN)
	    wait_for_write(server_fd);
	  else if (errno == EINTR)
	    continue;
	  else
	    die("Server write error: %m");
	}
      else
	{
	  l -= cnt;
	  z += cnt;
	}
    }
}
