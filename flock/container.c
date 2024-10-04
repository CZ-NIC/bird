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
  struct birdloop *loop;
  HASH(struct container_runtime) hash;
  struct container_runtime *cur_crt;
  int ctl[2]; /* socketpair filedescriptors */
} hcf;

static struct container_config {
  const char *hostname;
  const char *workdir;
  const char *basedir;
} ccf;

struct container_runtime {
  struct container_runtime *next;
  struct container_config ccf;
  uint hash;
  pid_t pid;
  sock *s;
  struct container_operation_callback {
    callback cb;
    sock *s;
    void *data;
  } *ccc;
  char data[];
};

#define CRT_KEY(c)	c->ccf.hostname, c->hash
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
  byte outbuf[128];
  linpool *lp = lp_new(&root_pool);
  struct cbor_writer *cw = cbor_init(outbuf, sizeof outbuf, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -4);
  cbor_add_int(cw, sig);
  ASSERT_DIE(write(fd, outbuf, cw->pt) == cw->pt);

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
container_mainloop(int fd)
{
  log(L_INFO "container mainloop with fd %d", fd);

  signal(SIGTERM, container_poweroff_sighandler);
  signal(SIGINT, container_poweroff_sighandler);
  signal(SIGCHLD, container_child_sighandler);

  /* Move to the workdir */
  linpool *lp = lp_new(&root_pool);

  if (strchr(ccf.basedir, ',') ||
      strchr(ccf.basedir, '=') ||
      strchr(ccf.basedir, '\\'))
    die("Refusing to work with paths containing chars: ,=\\");

  int wfd = GETDIR(lp_sprintf(lp, "%s%s", ccf.workdir[0] == '/' ? "" : "./", ccf.workdir));
  SYSCALL(fchdir, wfd);
  close(wfd); wfd = -1;

  close(GETDIR(lp_strdup(lp, "./upper")));
  close(GETDIR(lp_strdup(lp, "./tmp")));
  close(GETDIR(lp_strdup(lp, "./root")));

  bool cloneroot = !strcmp(ccf.basedir, "/");
  bool clonedev = cloneroot;
  if (cloneroot)
  {
    ccf.basedir = "./lower";
    close(GETDIR(lp_strdup(lp, "./lower")));
  }

  const char *overlay_mount_options = lp_sprintf(lp, "lowerdir=%s,upperdir=%s,workdir=%s",
      ccf.basedir, "./upper", "./tmp");
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
	log(L_INFO "ignoring unusable device %s", e->d_name);
	continue;
      }

      switch (s.st_mode & S_IFMT)
      {
	case S_IFSOCK:
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFREG:
	  log(L_INFO "bindmounting device %s", e->d_name);
	  SYSCALL(close, SYSCALL(open, path, O_WRONLY | O_CREAT, 0666));
	  int me = mount(orig, mpnt, NULL, MS_BIND, NULL);
	  if (me < 0)
	    log(L_ERR "failed to bindmount %s to %s: %m", orig, mpnt);

	  break;

	case S_IFLNK:
	  copylink(orig, s.st_size, path);
	  break;

	default:
	  log(L_INFO "ignoring device %s", e->d_name);
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
container_start(void)
{
  log(L_INFO "Requested to start a container, name %s, base %s, work %s",
      ccf.hostname, ccf.basedir, ccf.workdir);

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
    container_mainloop(fds[1]); /* this never returns */
    bug("container_mainloop has returned");
  }

  close(fds[1]);

  byte outbuf[128];
  linpool *lp = lp_new(&root_pool);
  struct cbor_writer *cw = cbor_init(outbuf, sizeof outbuf, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -2);
  cbor_add_int(cw, pid);
  struct iovec v = {
    .iov_base = outbuf,
    .iov_len = cw->pt,
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

static void
container_cleanup(struct container_runtime *crt)
{
  HASH_REMOVE(hcf.hash, CRT, crt);
  sk_close(crt->s);
  mb_free(crt);
}

static int
hypervisor_container_rx(sock *sk, uint _sz UNUSED)
{
  byte buf[128];
  ssize_t sz = read(sk->fd, buf, sizeof buf);
  if (sz < 0)
  {
    log(L_ERR "error reading data from %p (container_rx): %m", sk);
    sk_close(sk);
    return 0;
  }

  struct container_runtime *crt = sk->data;
  ASSERT_DIE(crt->s == sk);

  ASSERT_DIE(sz >= 3);
  ASSERT_DIE(buf[0] == 0xa1);

  switch (buf[1]) {
    case 0x23:
      log(L_INFO "container %s ended by signal %d", crt->ccf.hostname, buf[2]);
      if (crt->ccc)
	callback_activate(&crt->ccc->cb);
      container_cleanup(crt);
      break;

    default:
      log(L_ERR "container %s sent a weird message 0x%02x sz %d", crt->ccf.hostname, buf[1], sz);
      break;
  }

  return 0;
}

static void
hypervisor_container_err(sock *sk, int err)
{
  struct container_runtime *crt = sk->data;
  log(L_ERR "Container %s socket closed unexpectedly: %s", crt->ccf.hostname, strerror(err));
  container_cleanup(crt);
}

static int
hypervisor_container_forker_rx(sock *sk, uint _sz UNUSED)
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

  int e = recvmsg(sk->fd, &m, 0);
  if (e < 3)
  {
    log(L_ERR "Container forker RX hangup, what the hell");
    sk_close(sk);
    ev_send_loop(&main_birdloop, &poweroff_event);
    return 0;
  }

  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  memcpy(&sfd, CMSG_DATA(c), sizeof sfd);

  ASSERT_DIE(buf[0] == 0xa1);
  ASSERT_DIE(buf[1] == 0x21);
  pid_t pid;
  if (buf[2] < 0x18)
    pid = buf[2];
  else if (buf[2] == 24)
    pid = buf[3];
  else if (buf[2] == 25)
    pid = buf[3] << 8 + buf[4];
  else if (buf[3] == 26)
    pid = buf[3] << 32 + buf[4] << 24 + buf[5] << 16 + buf[6];
  else
    bug("not implemented");

  log(L_INFO "Machine started with PID %d", pid);

  sock *skl = sk_new(sk->pool);
  skl->type = SK_MAGIC;
  skl->rx_hook = hypervisor_container_rx;
  skl->err_hook = hypervisor_container_err;
  skl->fd = sfd;
  sk_set_tbsize(skl, 1024);

  if (sk_open(skl, sk->loop) < 0)
    bug("Machine control socket: sk_open failed");

  ASSERT_DIE(birdloop_inside(hcf.loop));

  ASSERT_DIE(hcf.cur_crt);
  skl->data = hcf.cur_crt;

  hcf.cur_crt->pid = pid;
  hcf.cur_crt->s = skl;
  if (hcf.cur_crt->ccc)
    callback_activate(&hcf.cur_crt->ccc->cb);
  hcf.cur_crt->ccc = NULL;
  hcf.cur_crt = NULL;

  return 0;
}

static void
hypervisor_container_forker_err(sock *sk, int e UNUSED)
{
  sk_close(sk);
}

/* The child */

static void
crt_err(sock *s, int err UNUSED)
{
  struct container_runtime *crt = s->data;
  s->data = crt->ccc->data;
  callback_cancel(&crt->ccc->cb);
  mb_free(crt->ccc);
  crt->ccc = NULL;
}

int
container_ctl_fd(const char *name)
{
  uint h = mem_hash(name, strlen(name));
  struct container_runtime *crt = HASH_FIND(hcf.hash, CRT, name, h);
  return (crt && crt->s) ? crt->s->fd : -1;
}

static void
container_created(callback *cb)
{
  SKIP_BACK_DECLARE(struct container_operation_callback, ccc, cb, cb);

  sock *s = ccc->s;
  linpool *lp = lp_new(s->pool);
  struct cbor_writer *cw = cbor_init(s->tbuf, s->tbsize, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -1);
  cbor_add_string(cw, "OK");
  sk_send(s, cw->pt);
  rfree(lp);

  s->data = ccc->data;
  sk_resume_rx(s->loop, s);

  mb_free(ccc);
}

void
hypervisor_container_request(sock *s, const char *name, const char *basedir, const char *workdir)
{
  birdloop_enter(hcf.loop);

  uint h = mem_hash(name, strlen(name));
  struct container_runtime *crt = HASH_FIND(hcf.hash, CRT, name, h);
  if (crt)
  {
    linpool *lp = lp_new(hcf.p);
    struct cbor_writer *cw = cbor_init(s->tbuf, s->tbsize, lp);
    cbor_open_block_with_length(cw, 1);
    cbor_add_int(cw, -127);
    cbor_add_string(cw, "BAD: Already exists");

    sk_send(s, cw->pt);

    birdloop_leave(hcf.loop);
    return;
  }

  uint nlen = strlen(name),
       blen = strlen(basedir),
       wlen = strlen(workdir);

  crt = mb_allocz(hcf.p, sizeof *crt + nlen + blen + wlen + 3);

  char *pos = crt->data;

  crt->ccf.hostname = pos;
  memcpy(pos, name, nlen + 1);
  pos += nlen + 1;

  crt->ccf.workdir = pos;
  memcpy(pos, workdir, wlen + 1);
  pos += wlen + 1;

  crt->ccf.basedir = pos;
  memcpy(pos, basedir, blen + 1);
  pos += blen + 1;

  crt->hash = h;

  struct container_operation_callback *ccc = mb_alloc(s->pool, sizeof *ccc);
  *ccc = (struct container_operation_callback) {
    .s = s,
    .data = s->data,
  };
  callback_init(&ccc->cb, container_created, s->loop);
  crt->ccc = ccc;

  HASH_INSERT(hcf.hash, CRT, crt);

  ASSERT_DIE(hcf.cur_crt == NULL);
  hcf.cur_crt = crt;

  log(L_INFO "requesting machine creation, socket %p", s);

  linpool *lp = lp_new(hcf.p);
  struct cbor_writer *cw = cbor_init(hcf.s->tbuf, hcf.s->tbsize, lp);
  cbor_open_block_with_length(cw, 3);
  cbor_add_int(cw, 0);
  cbor_add_string(cw, name);
  cbor_add_int(cw, 1);
  cbor_add_string(cw, basedir);
  cbor_add_int(cw, 2);
  cbor_add_string(cw, workdir);
  sk_send(hcf.s, cw->pt);
  rfree(lp);

  s->err_paused = crt_err;
  s->data = crt;
  sk_pause_rx(s->loop, s);

  birdloop_leave(hcf.loop);
}

static void
container_stopped(callback *cb)
{
  SKIP_BACK_DECLARE(struct container_operation_callback, ccc, cb, cb);

  sock *s = ccc->s;
  linpool *lp = lp_new(s->pool);
  struct cbor_writer *cw = cbor_init(s->tbuf, s->tbsize, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -1);
  cbor_add_string(cw, "OK");
  sk_send(s, cw->pt);
  rfree(lp);

  s->data = ccc->data;
  sk_resume_rx(s->loop, s);

  mb_free(ccc);
}

void
hypervisor_container_shutdown(sock *s, const char *name)
{
  birdloop_enter(hcf.loop);

  uint h = mem_hash(name, strlen(name));
  struct container_runtime *crt = HASH_FIND(hcf.hash, CRT, name, h);

  linpool *lp = lp_new(hcf.p);

  if (!crt || !crt->s)
  {
    struct cbor_writer *cw = cbor_init(s->tbuf, s->tbsize, lp);
    cbor_open_block_with_length(cw, 1);
    cbor_add_int(cw, -127);
    cbor_add_string(cw, "BAD: Not found");

    sk_send(s, cw->pt);
    rfree(lp);
    birdloop_leave(hcf.loop);
    return;
  }

  struct cbor_writer *cw = cbor_init(crt->s->tbuf, crt->s->tbsize, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, 0);
  write_item(cw, 7, 22);

  sk_send(crt->s, cw->pt);
  rfree(lp);

  struct container_operation_callback *ccc = mb_alloc(s->pool, sizeof *ccc);
  *ccc = (struct container_operation_callback) {
    .s = s,
    .data = s->data,
  };
  callback_init(&ccc->cb, container_stopped, s->loop);
  crt->ccc = ccc;

  s->err_paused = crt_err;
  s->data = crt;
  sk_pause_rx(s->loop, s);

  birdloop_leave(hcf.loop);
}

struct ccs_parser_context {
  struct cbor_parser_context *ctx;

  u64 bytes_consumed;
  u64 major_state;
};

#define CBOR_PARSER_ERROR bug

static struct ccs_parser_context ccx_, *ccx = &ccx_;

static void
hcf_parse(byte *buf, int size)
{
  ASSERT_DIE(size > 0);
  struct cbor_parser_context *ctx = ccx->ctx;

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

	    ccf = (struct container_config) {};

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

	    if (ccf.hostname)
	      CBOR_PARSER_ERROR("Duplicate argument 0 / hostname");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.hostname = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 3: /* workdir */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.workdir)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / workdir");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.workdir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 4: /* basedir */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.basedir)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / basedir");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.basedir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
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

    }

    /* End of array or map */
    while (cbor_parse_block_end(ctx))
    {
      switch (ccx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  /* Reinit the parser */
	  ctx->type = 0xff;
	  ccx->major_state = 0;
	  ctx->stack_countdown[0] = 1;
	  ccx->bytes_consumed = 0;

	  if (size > pos + 1)
	    hcf_parse(buf + pos + 1, size - pos - 1);
	  return;

	case 1: /* the mapping ended */
	  if (!ccf.hostname)
	    CBOR_PARSER_ERROR("Missing hostname");

	  if (!ccf.workdir)
	    CBOR_PARSER_ERROR("Missing workdir");

	  if (!ccf.basedir)
	    CBOR_PARSER_ERROR("Missing basedir");

	  container_start();

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
    hcf.s->rx_hook = hypervisor_container_forker_rx;
    hcf.s->err_hook = hypervisor_container_forker_err;
    sk_set_tbsize(hcf.s, 16384);
    hcf.s->fd = fds[0];
    close(fds[1]);

    HASH_INIT(hcf.hash, hcf.p, 6);

    if (sk_open(hcf.s, hcf.loop) < 0)
      bug("Container forker parent: sk_open failed");

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
