/*
 *	BIRD Internet Routing Daemon -- Helper for main.c
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MAIN_HELPER_H_
#define _BIRD_MAIN_HELPER_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "lib/birdlib.h"
#include "lib/socket.h"
#include "sysdep/config.h"
#include "nest/cli.h"
/*
 * Global variables
 */

extern int debug_flag;
extern char *config_name;
extern int run_in_foreground;
extern char *path_control_socket;
extern char *opt_list;
extern sock *cli_sk;
extern char *pid_file;
extern int pid_fd;
extern int parse_and_exit;
extern char *bird_name;
extern char *use_user;
extern char *use_group;

extern volatile int async_config_flag;
extern volatile int async_dump_flag;
extern volatile int async_shutdown_flag;

/*
 * Origin 'static' functions from main.c
 */

void async_dump(void);
void drop_gid(gid_t gid);
void add_num_const(char *name, int val);
void read_iproute_table(char *file, char *prefix, int max);
int cf_read(byte *dest, uint len, int fd);
int unix_read_config(struct config **cp, char *name);
struct config * read_config(void);
struct config * cmd_read_config(char *name);
void cmd_reconfig_msg(int r);
void cli_write(cli *c);
void cli_tx(sock *s);
int cli_rx(sock *s, int size UNUSED);
void cli_err(sock *s, int err);
int cli_connect(sock *s, int size UNUSED);
void cli_init_unix(uid_t use_uid, gid_t use_gid);
void open_pid_file(void);
void write_pid_file(void);
void unlink_pid_file(void);
void handle_sighup(int sig UNUSED);
void handle_sigusr(int sig UNUSED);
void handle_sigterm(int sig UNUSED);
void signal_init(void);
void usage(void);
char * get_bird_name(char *s, char *def);
uid_t get_uid(const char *s);
gid_t get_gid(const char *s);
void parse_args(int argc, char **argv);

#ifdef CONFIG_RESTRICTED_PRIVILEGES
#include "lib/syspriv.h"
#else
void drop_uid(uid_t uid);
#endif

#endif /* _BIRD_MAIN_HELPER_H_ */
