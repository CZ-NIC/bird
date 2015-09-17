/*
 *	BIRD -- Mockup of SSH Library for loading LibSSH using dlopen
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of SSH Library: http://www.libssh.org/
 *	(c) 2003-2009 by Aris Adamantiadis (SSH Library)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <dlfcn.h>
#include "nest/bird.h"
#include "lib/libssh.h"

#define FILENAME_OF_SHARED_OBJECT_LIBSSH "libssh.so"

static void *libssh;

/*
 * @return NULL if success
 * @return string with error if failed
 */
const char *
load_libssh(void)
{
  char *err_buf;

  libssh = dlopen(FILENAME_OF_SHARED_OBJECT_LIBSSH, RTLD_LAZY);
  if (!libssh)
  {
    /* This would be probably often repeated problem */
    char *help_msg = "You have to install libssh library.";
    err_buf = mb_alloc(&root_pool, 512); /* FIXME: free memory */
    bsnprintf(err_buf, 512, "%s. %s", dlerror(), help_msg);
    return err_buf;
  }

  dlerror(); /* Clear any existing error */

  ssh_new = (ssh_session (*)(void)) dlsym(libssh, "ssh_new");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_set_blocking = (void (*)(ssh_session, int)) dlsym(libssh, "ssh_set_blocking");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_options_set = (int (*)(ssh_session, enum ssh_options_e, const void *)) dlsym(libssh, "ssh_options_set");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_connect = (int (*)(ssh_session)) dlsym(libssh, "ssh_connect");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_get_fd = (socket_t (*)(ssh_session)) dlsym(libssh, "ssh_get_fd");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_is_server_known = (int (*)(ssh_session)) dlsym(libssh, "ssh_is_server_known");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_userauth_publickey_auto = (int (*)(ssh_session, const char *, const char *)) dlsym(libssh, "ssh_userauth_publickey_auto");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_get_error = (const char * (*)(void *)) dlsym(libssh, "ssh_get_error");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_get_error_code = (int (*)(void *)) dlsym(libssh, "ssh_get_error_code");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_disconnect = (void (*)(ssh_session)) dlsym(libssh, "ssh_disconnect");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_free = (void (*)(ssh_session)) dlsym(libssh, "ssh_free");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_new = (ssh_channel (*)(ssh_session)) dlsym(libssh, "ssh_channel_new");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_is_open = (int (*)(ssh_channel)) dlsym(libssh, "ssh_channel_is_open");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_close = (int (*)(ssh_channel)) dlsym(libssh, "ssh_channel_close");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_free = (void (*)(ssh_channel)) dlsym(libssh, "ssh_channel_free");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_open_session = (int (*)(ssh_channel)) dlsym(libssh, "ssh_channel_open_session");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_request_subsystem = (int (*)(ssh_channel, const char *)) dlsym(libssh, "ssh_channel_request_subsystem");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_read_nonblocking = (int (*)(ssh_channel, void *, uint32_t, int)) dlsym(libssh, "ssh_channel_read_nonblocking");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_is_eof = (int (*)(ssh_channel)) dlsym(libssh, "ssh_channel_is_eof");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_select = (int (*)(ssh_channel *, ssh_channel *, ssh_channel *, struct timeval *)) dlsym(libssh, "ssh_channel_select");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  ssh_channel_write = (int (*)(ssh_channel, const void *, uint32_t)) dlsym(libssh, "ssh_channel_write");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  return NULL;
}
