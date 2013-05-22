/*
 *	BIRD Client
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/* client.c callbacks */

void cleanup(void);
void input_start_list(void);
void input_stop_list(void);
void server_got_reply(char *x);

/* commands.c */

void cmd_build_tree(void);
void cmd_help(char *cmd, int len);
int cmd_complete(char *cmd, int len, char *buf, int again);
char *cmd_expand(char *cmd);

/* client_common.c */

#define STATE_PROMPT           0
#define STATE_CMD_SERVER       1
#define STATE_CMD_USER         2

#define SERVER_READ_BUF_LEN 4096

int handle_internal_command(char *cmd);
void submit_server_command(char *cmd);
void server_connect(void);
void server_read(void);
void server_send(char *cmd);
