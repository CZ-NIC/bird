#ifndef _BIRD_UNIX_TOOLS_H_
#define _BIRD_UNIX_TOOLS_H_

void parse_args(int argc, char **argv);
struct config *read_config(void);

void cli_init_unix(uid_t use_uid, gid_t use_gid);
void yi_init_unix(uid_t use_uid, gid_t use_gid);
void yi_init_file(void);
int unix_read_config(struct config **cp, const char *name);

extern int run_in_foreground;
extern char *use_user;
extern char *use_group;

extern struct cli_config initial_control_socket_config;
extern struct cli_config initial_yi_control_socket_config;

extern char *config_name;

#define path_control_socket initial_control_socket_config.name
#define path_control_socket_yi initial_yi_control_socket_config.name

static inline uid_t
get_uid(const char *s)
{
  struct passwd *pw;
  char *endptr;
  long int rv;

  if (!s)
    return 0;

  errno = 0;
  rv = strtol(s, &endptr, 10);

  if (!errno && !*endptr)
    return rv;

  pw = getpwnam(s);
  if (!pw)
    die("Cannot find user '%s'", s);

  return pw->pw_uid;
}

static inline gid_t
get_gid(const char *s)
{
  struct group *gr;
  char *endptr;
  long int rv;

  if (!s)
    return 0;

  errno = 0;
  rv = strtol(s, &endptr, 10);

  if (!errno && !*endptr)
    return rv;

  gr = getgrnam(s);
  if (!gr)
    die("Cannot find group '%s'", s);

  return gr->gr_gid;
}

/*
 *	PID file
 */

static char *pid_file;
static int pid_fd;

static inline void
open_pid_file(void)
{
  if (!pid_file)
    return;

  pid_fd = open(pid_file, O_WRONLY|O_CREAT, 0664);
  if (pid_fd < 0)
    die("Cannot create PID file %s: %m", pid_file);
}

static inline void
write_pid_file(void)
{
  int pl, rv;
  char ps[24];

  if (!pid_file)
    return;

  /* We don't use PID file for uniqueness, so no need for locking */

  pl = bsnprintf(ps, sizeof(ps), "%ld\n", (s64) getpid());
  if (pl < 0)
    bug("PID buffer too small");

  rv = ftruncate(pid_fd, 0);
  if (rv < 0)
    die("fruncate: %m");

  rv = write(pid_fd, ps, pl);
  if(rv < 0)
    die("write: %m");

  close(pid_fd);
}

static inline void
unlink_pid_file(void)
{
  if (pid_file)
    unlink(pid_file);
}


void watchdog_sigalrm(int sig UNUSED);

static inline char *
get_bird_name(char *s, char *def)
{
  char *t;
  if (!s)
    return def;
  t = strrchr(s, '/');
  if (!t)
    return s;
  if (!t[1])
    return def;
  return t+1;
}

extern char *opt_list;


#endif
