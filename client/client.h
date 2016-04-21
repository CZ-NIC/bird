/*
 *	BIRD Client
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CLIENT_H_
#define _BIRD_CLIENT_H_

#define REFRESH_SYMBOLS_CMD "refresh symbols"

extern int init, busy, interactive;
extern int term_lns, term_cls;

/* birdc.c / birdcl.c */

void input_start_list(void);
void input_stop_list(void);

void input_init(void);
void input_notify(int prompt);
void input_read(void);

void more_begin(void);
void more_end(void);

void cleanup(void);

/* commands.c */

void cmd_build_tree(void);
void cmd_help(char *cmd, int len);
int cmd_complete(char *cmd, int len, char *buf, int again);
char *cmd_expand(char *cmd);

/* client.c */

/* Client Symbol Flags: Types */
#define CLI_SF_CONSTANT		(1 << 0)
#define CLI_SF_VARIABLE		(1 << 1)
#define CLI_SF_FILTER		(1 << 2)
#define CLI_SF_FUNCTION		(1 << 3)
#define CLI_SF_PROTOCOL		(1 << 4)
#define CLI_SF_TABLE		(1 << 5)
#define CLI_SF_TEMPLATE		(1 << 6)
#define CLI_SF_INTERFACE	(1 << 7)

#define CLI_SF_OPTIONAL		(1 << 8) /* This node is optional not mandatory */
#define CLI_SF_PARAMETER	(1 << 9) /* A parameter/word will follow after this node */

/* Client Symbol Flags: Keywords */
#define CLI_SF_KW_ALL		(1 << 10)
#define CLI_SF_KW_OFF 		(1 << 11)


struct cli_symbol
{
  node n;
  const char *name;
  uint len;
  u32 flags;			/* CLI_SF_* */
};

void submit_command(char *cmd_raw);
void retrieve_symbols(void);
void add_keywords_to_symbols(void);
list *cli_get_symbol_list(void);
uint cli_get_symbol_maxlen(void);
void simple_input_read(void);

#endif
