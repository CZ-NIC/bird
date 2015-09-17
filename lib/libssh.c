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

ssh_session (*ssh_new)(void);
void (*ssh_set_blocking)(ssh_session session, int blocking);
int (*ssh_options_set)(ssh_session session, enum ssh_options_e type, const void *value);
int (*ssh_connect)(ssh_session session);
socket_t (*ssh_get_fd)(ssh_session session);
int (*ssh_is_server_known)(ssh_session session);
int (*ssh_userauth_publickey_auto)(ssh_session session, const char *username, const char *passphrase);
const char * (*ssh_get_error)(void *error);
int (*ssh_get_error_code)(void *error);
void (*ssh_disconnect)(ssh_session session);
void (*ssh_free)(ssh_session session);

ssh_channel (*ssh_channel_new)(ssh_session session);
int (*ssh_channel_is_open)(ssh_channel channel);
int (*ssh_channel_close)(ssh_channel channel);
void (*ssh_channel_free)(ssh_channel channel);
int (*ssh_channel_open_session)(ssh_channel channel);
int (*ssh_channel_request_subsystem)(ssh_channel channel, const char *subsystem);
int (*ssh_channel_read_nonblocking)(ssh_channel channel, void *dest, uint32_t count, int is_stderr);
int (*ssh_channel_is_eof)(ssh_channel channel);
int (*ssh_channel_select)(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, struct timeval * timeout);
int (*ssh_channel_write)(ssh_channel channel, const void *data, uint32_t len);


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
