#include "flock/flock.h"

#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/io-loop.h"
#include "lib/hash.h"

#include <dirent.h>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static struct hypervisor_container_forker {
  sock *s;
  pool *p;
  CBOR_STREAM_EMBED(stream, 4);
  struct birdloop *loop;
  HASH(struct container_runtime) hash;
  struct container_runtime *cur_crt;
  int ctl[2]; /* socketpair filedescriptors */
} hcf;

struct container_fork_request {
  CBOR_CHANNEL_EMBED(cch, 4);
  struct cbor_channel *ctl_ch;
  struct container_runtime *crt;
  int reply_state;
};

struct container_runtime {
  struct container_runtime *next;
  uint hash;
  pid_t pid;
  sock *s;
  CBOR_STREAM_EMBED(stream, 4);
  char hostname[];
};

#define CBOR_PARSER_ERROR FAIL

#define CRT_KEY(c)	c->hostname, c->hash
#define CRT_NEXT(c)	c->next
#define CRT_EQ(a,h,b,i)	((h) == (i)) && (!strcmp(a,b))
#define CRT_FN(a,h)	h

static sig_atomic_t poweroff, zombie;

static void
container_poweroff_sighandler(int signo)
{
  poweroff = signo;
}

static void
container_child_sighandler(int signo UNUSED)
{
  zombie = 1;
}

static int container_forker_fd = -1;

static void
container_poweroff(int fd, int sig)
{
  struct {
    struct cbor_writer w;
    struct cbor_writer_stack_item si[2];
    byte buf[128];
  } _cw;

  struct cbor_writer *cw = cbor_writer_init(&_cw.w, 2, _cw.buf, sizeof _cw.buf);
  CBOR_PUT_MAP(cw)
  {
    cbor_put_int(cw, -4);
    cbor_put_int(cw, sig);
  }
  ASSERT_DIE(cbor_writer_done(cw) == 1);
  s64 sz = cw->data.pos - cw->data.start;
  ASSERT_DIE(write(fd, cw->data.start, sz) == sz);

  unlink("/dev/log");
}

static void
container_zombie(void)
{
  zombie = 0;
  log(L_INFO "Zombie elimination routine invoked.");
  while (1) {
    int status;
    pid_t p = waitpid(-1, &status, WNOHANG);

    if (p < 0)
    {
      if (errno != ECHILD)
	log(L_ERR "Zombie elimination failed: %m");
      return;
    }

    if (p == 0)
      return;

    const char *coreinfo = WCOREDUMP(status) ? " (core dumped)" : "";

    if (WIFEXITED(status))
      log(L_INFO "Process %d ended with status %d%s", p, WEXITSTATUS(status), coreinfo);
    else if (WIFSIGNALED(status))
      log(L_INFO "Process %d exited by signal %d (%s)%s", p, WTERMSIG(status), strsignal(WTERMSIG(status)), coreinfo);
    else
      log(L_ERR "Process %d exited with a strange status %d", p, status);
  }
}

//#define SYSCALL(x, ...)	({ int _e = x(__VA_ARGS__); if (_e < 0) die("Failed to run %s at %s:%d: %m", #x, __FILE__, __LINE__); else log(L_TRACE "OK %s at %s:%d", #x, __FILE__, __LINE__); _e; })
#define SYSCALL(x, ...)	({ int _e = x(__VA_ARGS__); if (_e < 0) die("Failed to run %s at %s:%d: %m", #x, __FILE__, __LINE__); _e; })

#define RUN(...)  do {	    \
    pid_t pid = fork();	    \
    if (pid) waitpid(pid, NULL, 0); \
    else { execlp(__VA_ARGS__, NULL); bug("exec %s failed: %m", #__VA_ARGS__); }  \
} while (0)


static int
container_getdir(char *path)
{
  int e = open(path, O_DIRECTORY | O_PATH | O_RDWR);
  if ((e >= 0) || (errno != ENOENT))
    return e;

  /* Split the path */
  char *sl = strrchr(path, '/');
  char *name = sl+1;

  if (sl == path)
    path = "/";
  else
  {
    while (sl && sl[1] == 0)
    {
      /* Trailing slash removal */
      sl[0] = 0;
      sl = strrchr(path, '/');
    }

    if (!sl)
      bug("Getdir failed, empty sl");
  }

  /* Open the parent directory */
  *sl = 0;
  int fd = container_getdir(path);
  if (fd < 0)
    return fd;

  for (uint i=0; i<256; i++)
  {
    e = mkdirat(fd, name, 0755);
    if ((e < 0) && (errno != EEXIST))
    {
      close(fd);
      return e;
    }

    e = openat(fd, name, O_DIRECTORY | O_PATH | O_RDWR);
    if ((e >= 0) || (errno != ENOENT))
    {
      close(fd);
      return e;
    }
  }

  die("Somebody is messing with the filesystem too badly.");
}

static void
copylink(const char *src, int sz, const char *dst)
{
  char *contents = alloca(sz + 1);
  int xsz = SYSCALL(readlink, src, contents, sz);
  contents[xsz] = 0;
//  log(L_INFO "symlinking device %s -> %s", dst, contents);
  int se = symlink(contents, dst);
  if (se < 0)
//    die("failed to symlink %s: %m", dst);
    log(L_ERR "failed to symlink %s: %m", dst);
}

#define GETDIR(_path)  ({ char *path = _path; int fd = container_getdir(path); if (fd < 0) die("Failed to get the directory %s: %m", path); fd; })
#define MKDIR(_path)  close(GETDIR(tmp_strdup(_path)))

struct container_logger {
  struct birdloop *loop;
  pool *p;
  sock *rs;
  sock *ws;
};

static int
container_logger_rx(sock *sk, uint sz)
{
  struct container_logger *clg = sk->data;
  if (clg->ws->tpos + sz >= clg->ws->tbuf + clg->ws->tbsize)
    log(L_INFO "dropping a log message");

  memcpy(clg->ws->tpos, sk->rbuf, sz);
  clg->ws->tpos[sz] = '\n';

  if (clg->ws->tpos == clg->ws->tbuf)
    sk_send(clg->ws, sz + 1);
  else
    clg->ws->tpos += sz + 1;

  return 0;
}

static void
container_logger_rerr(sock *sk UNUSED, int err)
{
  if (!err)
    bug("what");

  die("Logger receiver socket closed unexpectedly: %s", strerror(err));
}

static void
container_logger_werr(sock *sk UNUSED, int err)
{
  die("Logger writer closed unexpectedly: %s", strerror(err));
}

static void
container_init_logger(void)
{
  struct birdloop *loop = birdloop_new(&root_pool, DOMAIN_ORDER(proto), 0, "Logger");
  birdloop_enter(loop);
  pool *p = rp_new(birdloop_pool(loop), birdloop_domain(loop), "Logger pool");
  sock *s = sk_new(p);
  s->type = SK_MAGIC;
  s->rx_hook = container_logger_rx;
  s->err_hook = container_logger_rerr;
  sk_set_rbsize(s, 16384);

  unlink("/dev/log");
  s->fd = SYSCALL(socket, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  union {
    struct sockaddr sa;
    struct sockaddr_un un;
  } sa;
  sa.un.sun_family = AF_UNIX;
  strcpy(sa.un.sun_path, "/dev/log");
  SYSCALL(bind, s->fd, &sa.sa, sizeof sa.un);

  struct container_logger *clg = mb_allocz(p, sizeof *clg);
  clg->loop = loop;
  clg->p = p;
  clg->rs = s;
  s->data = clg;

  if (sk_open(clg->rs, clg->loop) < 0)
    bug("Logger failed in sk_open(r): %m");

  clg->rs->type = SK_UDP;

  s = clg->ws = sk_new(p);
  s->data = clg;
  s->type = SK_MAGIC;
  s->err_hook = container_logger_werr;
  sk_set_tbsize(s, 16384);

  MKDIR("/var/log");
  s->fd = SYSCALL(open, "/var/log/syslog", O_WRONLY | O_CREAT, 0640);

  if (sk_open(clg->ws, clg->loop) < 0)
    bug("Logger failed in sk_open(w): %m");

  s->type = SK_UNIX;

  birdloop_leave(loop);
}

static void
container_mainloop(int fd, struct flock_machine_container_config *ccf)
{
  log(L_INFO "container mainloop with fd %d", fd);

  signal(SIGTERM, container_poweroff_sighandler);
  signal(SIGINT, container_poweroff_sighandler);
  signal(SIGCHLD, container_child_sighandler);

  /* Move to the workdir */
  linpool *lp = lp_new(&root_pool);

  if (strchr(ccf->basedir, ',') ||
      strchr(ccf->basedir, '=') ||
      strchr(ccf->basedir, '\\'))
    die("Refusing to work with paths containing chars: ,=\\");

  int wfd = GETDIR(lp_sprintf(lp, "%s%s", ccf->workdir[0] == '/' ? "" : "./", ccf->workdir));
  SYSCALL(fchdir, wfd);
  close(wfd); wfd = -1;

  close(GETDIR(lp_strdup(lp, "./upper")));
  close(GETDIR(lp_strdup(lp, "./tmp")));
  close(GETDIR(lp_strdup(lp, "./root")));

  bool cloneroot = !strcmp(ccf->basedir, "/");
  bool clonedev = cloneroot;
  if (cloneroot)
  {
    ccf->basedir = "./lower";
    close(GETDIR(lp_strdup(lp, "./lower")));
  }

  const char *overlay_mount_options = lp_sprintf(lp, "lowerdir=%s,upperdir=%s,workdir=%s",
      ccf->basedir, "./upper", "./tmp");
  SYSCALL(mount, "overlay", "./root", "overlay", 0, overlay_mount_options);

  if (cloneroot)
  {
#define BINDMOUNT(path)	do { \
  struct stat s; \
  SYSCALL(lstat, "/" #path, &s); \
  switch (s.st_mode & S_IFMT) { \
    case S_IFLNK: \
      copylink("/" #path, s.st_size, "./lower/" #path); \
      break; \
    case S_IFDIR: \
      close(GETDIR(lp_strdup(lp, "./lower/" #path))); \
      SYSCALL(mount, "/" #path, "./root/" #path, NULL, MS_BIND | MS_REC, NULL); \
      break; \
  } \
} while (0)
    BINDMOUNT(bin);
    BINDMOUNT(etc);
    BINDMOUNT(lib);
    BINDMOUNT(lib32);
    BINDMOUNT(lib64);
    BINDMOUNT(libx32);
    BINDMOUNT(sbin);
    BINDMOUNT(usr);

    close(GETDIR(lp_strdup(lp, "./lower/dev/pts")));
    symlink("/dev/pts/ptmx", "./lower/dev/ptmx");

    DIR *x = opendir("/dev");
    for (struct dirent *e; e = readdir(x); )
    {
      if (!strcmp(e->d_name, ".")
	  || !strcmp(e->d_name, "..")
	  || !strcmp(e->d_name, "ptmx")
	  || !strcmp(e->d_name, "log")
	 )
	continue;

      const char *path = lp_sprintf(lp, "./lower/dev/%s", e->d_name);
      const char *mpnt = lp_sprintf(lp, "./root/dev/%s", e->d_name);
      const char *orig = lp_sprintf(lp, "/dev/%s", e->d_name);

      struct stat s;
      SYSCALL(lstat, orig, &s);
      if (!(s.st_mode & S_IRWXO))
      {
//	log(L_INFO "ignoring unusable device %s", e->d_name);
	continue;
      }

      switch (s.st_mode & S_IFMT)
      {
	case S_IFSOCK:
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFREG:
//	  log(L_INFO "bindmounting device %s", e->d_name);
	  SYSCALL(close, SYSCALL(open, path, O_WRONLY | O_CREAT, 0666));
	  int me = mount(orig, mpnt, NULL, MS_BIND, NULL);
	  if (me < 0)
	    log(L_ERR "failed to bindmount %s to %s: %m", orig, mpnt);

	  break;

	case S_IFLNK:
	  copylink(orig, s.st_size, path);
	  break;

	default:
//	  log(L_INFO "ignoring device %s", e->d_name);
	  break;
      }
    }
  }

  MKDIR("./lower/proc");
  MKDIR("./lower/sys");
  MKDIR("./lower/run");
  MKDIR("./lower/tmp");
  
  SYSCALL(chroot, "./root");
  SYSCALL(chdir, "/");

  /* Remounting proc to reflect the new PID namespace */
  SYSCALL(mount, "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  SYSCALL(mount, "sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  SYSCALL(mount, "tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
  SYSCALL(mount, "tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
  SYSCALL(mount, "devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "ptmxmode=600");

  container_init_logger();

  /* Run worker threads */
  struct thread_config tc = {};
  bird_thread_commit(&tc);

  while (1)
  {
    struct pollfd pfd = {
      .fd = fd,
      .events = POLLIN,
    };

    sigset_t newmask;
    sigemptyset(&newmask);

    int res = ppoll(&pfd, 1, NULL, &newmask);

    if ((res < 0) && (errno != EINTR))
      log(L_INFO "ppoll returned -1: %m");

    if (poweroff)
    {
      container_poweroff(fd, poweroff);
      exit(0);
    }

    if (zombie)
      container_zombie();

    if (pfd.revents & POLLIN)
    {
      int sfd = -1;
      byte buf[128], cbuf[CMSG_SPACE(sizeof sfd)];
      struct iovec v = {
	.iov_base = buf,
	.iov_len = sizeof buf,
      };
      struct msghdr m = {
	.msg_iov = &v,
	.msg_iovlen = 1,
	.msg_control = &cbuf,
	.msg_controllen = sizeof cbuf,
      };

      int sz = recvmsg(fd, &m, 0);
      if (sz < 0)
      {
	log(L_ERR "error reading data from control socket: %m");
	exit(1);
      }

      if (sz == 0)
      {
	log(L_INFO "control socket closing, shutdown");
	exit(0);
      }

      ASSERT_DIE(sz >= 3);
      ASSERT_DIE(buf[0] == 0xa1);
      switch (buf[1]) {
	case 0:
	  ASSERT_DIE(buf[2] == 0xf6);
	  container_poweroff(fd, 0);
	  exit(0);
	  break;

	case 0x21:
	  ASSERT_DIE(buf[2] == 0xf6);
	  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
	  memcpy(&sfd, CMSG_DATA(c), sizeof sfd);

	  int e = fork();
	  if (e < 0) bug("Cannot fork: %m");
	  if (e == 0) {
	    int fd = accept(sfd, NULL, 0);
	    if (fd < 0)
	    {
	      log(L_ERR "failed to accept telnet connection: %m");
	      exit(1);
	    }
	    log(L_INFO "telnet connected");

	    close(0);
	    close(1);
//	    close(2);

	    dup2(fd, 0);
	    dup2(fd, 1);

	    /* Unblock signals */
	    sigset_t newmask;
	    sigemptyset(&newmask);
	    sigprocmask(SIG_SETMASK, &newmask, NULL);

	    /* Exec the telnet */

//	    e = execl("/usr/bin/strace", "strace", "-o", "/xxx", "-ff", "telnetd", "-E", "/bin/bash", NULL);
	    e = execl("/usr/sbin/telnetd", "telnetd", "-E", "/bin/bash", NULL);
	    log(L_ERR "failed to execl telnet: %m");
	    exit(42);
	  }
	  close(sfd);
	  break;

	default:
	  log(L_ERR "unknown command on control socket: %d", buf[1]);
	  break;
      }
    }
  }
}

static uint container_counter = 0;

static void
container_start(struct flock_machine_container_config *ccf)
{
  log(L_INFO "Requested to start a container, name %s, base %s, work %s",
      ccf->cf.name, ccf->basedir, ccf->workdir);

  pid_t pid = fork();
  if (pid < 0)
    die("Failed to fork container (parent): %m");

  if (pid)
  {
    log(L_INFO "Forked container parent pid %d", pid);
    container_counter++;
    int status;
    pid_t pp = waitpid(pid, &status, 0);

    if (pp < 0)
      die("Failed to waitpid %d: %m");

    if (pp != pid)
      die("Waited pid %d instead of %d, wtf", pp, pid);

    const char *coreinfo = WCOREDUMP(status) ? " (core dumped)" : "";

    if (WIFEXITED(status))
      log(L_INFO "Process %d ended with status %d%s", pp, WEXITSTATUS(status), coreinfo);
    else if (WIFSIGNALED(status))
      log(L_INFO "Process %d exited by signal %d (%s)%s", pp, WTERMSIG(status), strsignal(WTERMSIG(status)), coreinfo);
    else
      log(L_ERR "Process %d exited with a strange status %d", pp, status);

    return;
  }

  int e = unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWTIME | CLONE_NEWNET);
  if (e < 0)
    die("Failed to unshare container: %m");

  /* Mask signals for forking and other fragile stuff */
  sigset_t oldmask;
  sigset_t newmask;
  sigemptyset(&newmask);
#define KILLABLE_SIGNALS  SIGINT, SIGTERM, SIGHUP, SIGQUIT
#define FROB(x) sigaddset(&newmask, x);
  MACRO_FOREACH(FROB, KILLABLE_SIGNALS);
#undef FROB
  sigprocmask(SIG_BLOCK, &newmask, &oldmask);

  /* create socketpair before forking to do communication */
  int fds[2];
  e = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  log("container fork socketpair: %d %d", fds[0], fds[1]);

  pid = fork();
  if (pid < 0)
    die("Failed to fork container (child): %m");

  if (!pid)
  {
    /* Cleanup in control sockets */
    close(hcf.ctl[1]);
    close(fds[0]);

    ASSERT_DIE(container_counter < 0x6000);
    this_thread_id -= (container_counter << 1) + 0x3000 ;
    container_mainloop(fds[1], ccf); /* this never returns */
    bug("container_mainloop has returned");
  }

  close(fds[1]);

  struct {
    struct cbor_writer w;
    struct cbor_writer_stack_item si[2];
    byte buf[128];
  } _cw;

  struct cbor_writer *cw = cbor_writer_init(&_cw.w, 2, _cw.buf, sizeof _cw.buf);
  CBOR_PUT_MAP(cw)
  {
    cbor_put_int(cw, -2);
    cbor_put_int(cw, pid);
  }

  struct iovec v = {
    .iov_base = cw->data.start,
    .iov_len = cw->data.pos - cw->data.start,
  };
  byte cbuf[CMSG_SPACE(sizeof fds[0])];
  struct msghdr m = {
    .msg_iov = &v,
    .msg_iovlen = 1,
    .msg_control = &cbuf,
    .msg_controllen = sizeof cbuf,
  };
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof fds[0]);
  memcpy(CMSG_DATA(c), &fds[0], sizeof fds[0]);

  log(L_INFO "Sending socket");

  e = sendmsg(container_forker_fd, &m, 0);
  if (e < 0)
    log(L_ERR "Failed to send socket: %m");

  log(L_INFO "Socket sent");
  exit(0);
}

/* The Parent */

static struct container_runtime *
container_find_by_name(const char *name)
{
  uint h = mem_hash(name, strlen(name));
  return HASH_FIND(hcf.hash, CRT, name, h);
}

struct cbor_channel *
container_get_channel(const char *name)
{
  struct container_runtime *crt = container_find_by_name(name);
  return crt ? cbor_channel_new(&crt->stream) : NULL;
}

static void
container_cleanup(struct container_runtime *crt)
{
  HASH_REMOVE(hcf.hash, CRT, crt);
  sk_close(crt->s);
  mb_free(crt);
}

struct container_ctl_msg {
  CBOR_CHANNEL_EMBED(cch, 4);
  struct cbor_channel *ctl_ch;
  int msg_state;
  int down_signal;
};

static enum cbor_parse_result
container_ctl_parse(struct cbor_channel *cch, enum cbor_parse_result res)
{
  SKIP_BACK_DECLARE(struct container_ctl_msg, ccc, cch, cch);
  SKIP_BACK_DECLARE(struct container_runtime, crt, stream, cch->stream);
  struct cbor_parser_context *ctx = &crt->stream.parser;

#define FAIL(...) do { log(L_ERR "Container ctl parse: " __VA_ARGS__); return CPR_ERROR; } while (0)

  switch (res)
  {
    case CPR_MAJOR:
      switch (ccc->msg_state)
      {
	case 0:
	  if ((ctx->type != CBOR_MAP) || (ctx->value != 1))
	    FAIL("Expected map of size 1, got %d-%d", ctx->type, ctx->value);

	  ccc->msg_state = 1;
	  return CPR_MORE;

	case 1:
	  if ((ctx->type != CBOR_NEGINT) || (ctx->value != 3))
	    FAIL("Expected key -4, got %d-%d", ctx->type, ctx->value);

	  ccc->msg_state = 2;
	  return CPR_MORE;

	case 2:
	  CBOR_PARSE_ONLY(ctx, POSINT, ccc->down_signal);
	  ccc->msg_state = 3;
	  return CPR_MORE;

	default:
	  FAIL("Input overflow to state %d", ccc->msg_state);
      }
      bug("Overrun switch");

    case CPR_STR_END:
      FAIL("Unexpected string end");

    case CPR_BLOCK_END:
      switch (ccc->msg_state) {
	case 3:
	  ccc->msg_state = 4;
	  break;

	default:
	  FAIL("Unexpected block end in state %d", ccc->msg_state);
      }
      break;

    case CPR_ERROR:
    case CPR_MORE:
      FAIL("Invalid input");
  }
  
  log(L_INFO "container %s ended by signal %d", crt->hostname, ccc->down_signal);
  container_cleanup(crt);

#undef FAIL
  return CPR_BLOCK_END;
}

static enum cbor_parse_result
container_fork_request_reply(struct cbor_channel *cch, enum cbor_parse_result res)
{
  ASSERT_DIE(cch->stream == &hcf.stream);

  SKIP_BACK_DECLARE(struct container_fork_request, cfr, cch, cch);
  struct container_runtime *crt = cfr->crt;
  struct cbor_parser_context *ctx = &cch->stream->parser;
  
#define FAIL(...) do { log(L_ERR "Container fork request reply: " __VA_ARGS__); return CPR_ERROR; } while (0)

  switch (res)
  {
    case CPR_MAJOR:
      switch (cfr->reply_state) {
	case 0:
	  if ((ctx->type != CBOR_MAP) || (ctx->value != 1))
	    FAIL("Expected map of size 1, got %d-%d", ctx->type, ctx->value);

	  cfr->reply_state = 1;
	  return CPR_MORE;

	case 1:
	  if ((ctx->type != CBOR_NEGINT) || (ctx->value != 1))
	    FAIL("Expected key -2, got %d-%d", ctx->type, ctx->value);

	  cfr->reply_state = 2;
	  return CPR_MORE;

	case 2:
	  CBOR_PARSE_ONLY(ctx, POSINT, crt->pid);
	  cfr->reply_state = 3;
	  return CPR_MORE;

	default:
	  FAIL("Input overflow to state %d", cfr->reply_state);
      }
      bug("Overrun switch");

    case CPR_STR_END:
      FAIL("Unexpected string end");

    case CPR_BLOCK_END:
      switch (cfr->reply_state) {
	case 3:
	  cfr->reply_state = 4;
	  break;

	default:
	  FAIL("Unexpected block end in state %d", cfr->reply_state);
      }
      break;

    case CPR_ERROR:
    case CPR_MORE:
      FAIL("Invalid input");
  }
  
  log(L_INFO "Machine started with PID %d", crt->pid);

  if (hcf.s->rxfd < 0)
    FAIL("No control socket of the new machine");

  ASSERT_DIE(birdloop_inside(hcf.loop));

  sock *skl = sk_new(hcf.p);
  skl->type = SK_MAGIC;

  skl->fd = hcf.s->rxfd;
  hcf.s->rxfd = -1;

  if (sk_open(skl, hcf.loop) < 0)
    bug("Machine control socket: sk_open failed");

  sk_set_tbsize(skl, 1024);
  skl->type = SK_UNIX_MSG;

  crt->s = skl;
  cbor_stream_attach(&crt->stream, skl);

  CBOR_REPLY(cfr->ctl_ch, cw)
    CBOR_PUT_MAP(cw)
    {
      cbor_put_int(cw, -1);
      cbor_put_string(cw, "OK");
    }

  cbor_channel_done(&cfr->cch);

  return CPR_BLOCK_END;
#undef FAIL
}

void
hypervisor_container_start(struct cbor_channel *cch, struct flock_machine_container_config *ccf)
{
  birdloop_enter(hcf.loop);

#define FAIL(id, msg) do { \
  CBOR_REPLY(cch, cw) CBOR_PUT_MAP(cw) { \
    cbor_put_int(cw, id); cbor_put_string(cw, msg);\
  } cbor_channel_done(cch); \
  birdloop_leave(hcf.loop); \
  return; } while (0)

  if (!ccf->cf.name)
    FAIL(-101, "Machine name not specified");

  if (!ccf->workdir)
    FAIL(-102, "Machine workdir not specified");

  if (!ccf->basedir)
    FAIL(-103, "Machine basedir not specified");

  const char *name = ccf->cf.name;
  uint h = mem_hash(name, strlen(name));
  struct container_runtime *crt = HASH_FIND(hcf.hash, CRT, name, h);
  if (crt)
    FAIL(-127, "Container already exists");

  uint nlen = strlen(name);
  crt = mb_allocz(hcf.p, sizeof *crt + nlen + 1);
  crt->hash = h;
  memcpy(crt->hostname, name, nlen + 1);

  HASH_INSERT(hcf.hash, CRT, crt);

  /* Create a new channel atop the forker stream */
  log(L_INFO "requesting machine creation, name %s", name);
  SKIP_BACK_DECLARE(struct container_fork_request, cfr, cch, cbor_channel_new(&hcf.stream));
  cfr->ctl_ch = cch;
  cfr->crt = crt;
  cfr->cch.parse = container_fork_request_reply;

  crt->stream.parse = container_ctl_parse;
  CBOR_STREAM_INIT(crt, stream, cch, hcf.p, struct container_ctl_msg);

  CBOR_REPLY(&cfr->cch, cw)
    CBOR_PUT_MAP(cw)
    {
      cbor_put_int(cw, 0);
      cbor_put_string(cw, name);
      cbor_put_int(cw, 1);
      cbor_put_string(cw, ccf->basedir);
      cbor_put_int(cw, 2);
      cbor_put_string(cw, ccf->workdir);
    }

#undef FAIL
  birdloop_leave(hcf.loop);
}

static enum cbor_parse_result
container_stopped(struct cbor_channel *cch, enum cbor_parse_result res)
{
  SKIP_BACK_DECLARE(struct container_ctl_msg, ccc, cch, cch);
  SKIP_BACK_DECLARE(struct container_runtime, crt, stream, cch->stream);
  struct cbor_parser_context *ctx = &crt->stream.parser;

#define FAIL(...) do { log(L_ERR "Container stopped parse: " __VA_ARGS__); return CPR_ERROR; } while (0)

  switch (res)
  {
    case CPR_MAJOR:
      switch (ccc->msg_state)
      {
	case 0:
	  if ((ctx->type != CBOR_MAP) || (ctx->value != 1))
	    FAIL("Expected map of size 1, got %d-%d", ctx->type, ctx->value);

	  ccc->msg_state = 1;
	  return CPR_MORE;

	case 1:
	  if ((ctx->type != CBOR_NEGINT) || (ctx->value != 3))
	    FAIL("Expected key -4, got %d-%d", ctx->type, ctx->value);

	  ccc->msg_state = 2;
	  return CPR_MORE;

	case 2:
	  CBOR_PARSE_ONLY(ctx, POSINT, ccc->down_signal);
	  ccc->msg_state = 3;
	  return CPR_MORE;

	default:
	  FAIL("Input overflow to state %d", ccc->msg_state);
      }
      bug("Overrun switch");

    case CPR_STR_END:
      FAIL("Unexpected string end");

    case CPR_BLOCK_END:
      switch (ccc->msg_state) {
	case 3:
	  ccc->msg_state = 4;
	  break;

	default:
	  FAIL("Unexpected block end in state %d", ccc->msg_state);
      }
      break;

    case CPR_ERROR:
    case CPR_MORE:
      FAIL("Invalid input");
  }

  CBOR_REPLY(ccc->ctl_ch, cw)
    CBOR_PUT_MAP(cw)
    {
      cbor_put_int(cw, -1);
      cbor_put_string(cw, "OK");
    }

  cbor_channel_done(&ccc->cch);
  return CPR_BLOCK_END;
#undef FAIL
}

void
hypervisor_container_shutdown(struct cbor_channel *cch, struct flock_machine_container_config *ccf)
{
  birdloop_enter(hcf.loop);

  const char *name = ccf->cf.name;
  uint h = mem_hash(name, strlen(name));
  struct container_runtime *crt = HASH_FIND(hcf.hash, CRT, name, h);

  if (!crt || !crt->s)
  {
    CBOR_REPLY(cch, cw)
      CBOR_PUT_MAP(cw)
      {
	cbor_put_int(cw, -127);
	cbor_put_string(cw, "BAD: Not found");
      }

    cbor_channel_done(cch);
    birdloop_leave(hcf.loop);
    return;
  }

  SKIP_BACK_DECLARE(struct container_ctl_msg, ccr, cch, cbor_channel_new(&crt->stream));
  CBOR_REPLY(&ccr->cch, cw)
    CBOR_PUT_MAP(cw)
    {
      cbor_put_int(cw, 0);
      cbor_put_null(cw);
    }

  ccr->cch.parse = container_stopped;
  ccr->ctl_ch = cch;

  birdloop_leave(hcf.loop);
}

struct ccs_parser_context {
  struct cbor_parser_context *ctx;

  u64 bytes_consumed;
  u64 major_state;
};

#undef CBOR_PARSER_ERROR
#define CBOR_PARSER_ERROR bug

static struct ccs_parser_context ccx_, *ccx = &ccx_;

static void
hcf_parse(byte *buf, int size)
{
  ASSERT_DIE(size > 0);
  struct cbor_parser_context *ctx = ccx->ctx;

  static struct flock_machine_container_config ccf;

  for (int pos = 0; pos < size; pos++)
  {
    switch (cbor_parse_byte(ctx, buf[pos]))
    {
      case CPR_ERROR:
	bug("CBOR parser failure: %s", ctx->error);

      case CPR_MORE:
	continue;

      case CPR_MAJOR:
	/* Check type acceptance */
	switch (ccx->major_state)
	{
	  case 0: /* toplevel */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    ccf = (struct flock_machine_container_config) {};

	    ccx->major_state = 1;
	    break;

	  case 1: /* inside toplevel mapping */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 3)
	      CBOR_PARSER_ERROR("Mapping key too high, got %lu", ctx->value);

	    ccx->major_state = ctx->value + 2;
	    break;

	  case 2: /* machine hostname */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.cf.name)
	      CBOR_PARSER_ERROR("Duplicate argument 0 / hostname");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.cf.name = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 3: /* basedir */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.workdir)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / basedir");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.basedir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 4: /* workdir */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.workdir)
	      CBOR_PARSER_ERROR("Duplicate argument 2 / workdir");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.workdir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  default:
	    bug("invalid parser state");
	}
	break;

      case CPR_STR_END:
	/* Bytes read completely! */
	switch (ccx->major_state)
	{
	  case 2:
	  case 3:
	  case 4:
	    ccx->major_state = 1;
	    break;

	  default:
	    bug("Unexpected state to end a (byte)string in");
	  /* Code to run at the end of a (byte)string */
	}
	break;

      case CPR_BLOCK_END:
	bug("invalid parser state");
    }

    /* End of array or map */
    while (cbor_parse_block_end(ctx))
    {
      switch (ccx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  /* Reinit the parser */
	  ccx->major_state = 0;
	  ccx->bytes_consumed = 0;
	  cbor_parser_reset(ccx->ctx);

	  if (size > pos + 1)
	    hcf_parse(buf + pos + 1, size - pos - 1);
	  return;

	case 1: /* the mapping ended */
	  if (!ccf.cf.name)
	    CBOR_PARSER_ERROR("Missing hostname");

	  if (!ccf.workdir)
	    CBOR_PARSER_ERROR("Missing workdir");

	  if (!ccf.basedir)
	    CBOR_PARSER_ERROR("Missing basedir");

	  container_start(&ccf);

	  ccx->major_state = 0;
	  break;

	default:
	  bug("Unexpected state to end a mapping in");
      }
    }
  }

  ccx->bytes_consumed += size;
}

void
hypervisor_container_fork(void)
{
  int e, *fds = hcf.ctl;

  /* create socketpair before forking to do communication */
  e = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  e = fork();
  if (e < 0)
    die("Failed to fork container forker: %m");

  if (e)
  {
    /* parent side */
    hcf.loop = birdloop_new(&root_pool, DOMAIN_ORDER(proto), 0, "Container forker");

    birdloop_enter(hcf.loop);
    hcf.p = rp_new(birdloop_pool(hcf.loop), birdloop_domain(hcf.loop), "Container forker pool");
    hcf.s = sk_new(hcf.p);
    hcf.s->type = SK_MAGIC;
    /* Set the hooks and fds according to the side we are at */
    sk_set_tbsize(hcf.s, 16384);
    sk_set_rbsize(hcf.s, 128);
    hcf.s->fd = fds[0];
    close(fds[1]);

    HASH_INIT(hcf.hash, hcf.p, 6);

    if (sk_open(hcf.s, hcf.loop) < 0)
      bug("Container forker parent: sk_open failed");

    hcf.s->type = SK_UNIX_MSG;
    hcf.stream.parse = container_fork_request_reply;
    CBOR_STREAM_INIT(&hcf, stream, cch, hcf.p, struct container_fork_request);
    cbor_stream_attach(&hcf.stream, hcf.s);

    birdloop_leave(hcf.loop);
    return;
  }

  /* noreturn child side */
  close(fds[0]);
  hexp_cleanup_after_fork();
  container_forker_fd = fds[1];

  this_thread_id |= 0xf000;

  /* initialize the forker */
  ccx->ctx = cbor_parser_new(&root_pool, 2);

  while (true)
  {
    byte buf[4096];

    ssize_t rx = read(fds[1], buf, sizeof buf);

    times_update();

    if (rx == 0)
    {
      log(L_INFO "Container forker socket closed, exiting");
      exit(0);
    }

    if (rx < 0)
      bug("Container forker child: failed to read: %m");

    hcf_parse(buf, rx);
  }
}