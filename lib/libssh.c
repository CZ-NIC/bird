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

struct ssh_function {
  void **fn;
  const char *name;
};

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

#define SSH_FN(x) { .fn = (void **) &x, .name = #x }
static struct ssh_function all_ssh_fn[] = {
    SSH_FN(ssh_new),
    SSH_FN(ssh_set_blocking),
    SSH_FN(ssh_options_set),
    SSH_FN(ssh_connect),
    SSH_FN(ssh_get_fd),
    SSH_FN(ssh_is_server_known),
    SSH_FN(ssh_userauth_publickey_auto),
    SSH_FN(ssh_get_error),
    SSH_FN(ssh_get_error_code),
    SSH_FN(ssh_disconnect),
    SSH_FN(ssh_free),
    SSH_FN(ssh_channel_new),
    SSH_FN(ssh_channel_is_open),
    SSH_FN(ssh_channel_close),
    SSH_FN(ssh_channel_free),
    SSH_FN(ssh_channel_open_session),
    SSH_FN(ssh_channel_request_subsystem),
    SSH_FN(ssh_channel_read_nonblocking),
    SSH_FN(ssh_channel_is_eof),
    SSH_FN(ssh_channel_select),
    SSH_FN(ssh_channel_write),
};
#undef SSH_FN

static void *libssh;

/**
 * load_libssh - Prepare all ssh_* functions
 *
 * Initialize for use all ssh_* functions. Returns normally NULL.
 * If an error occurs then returns static string with the error description.
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

  for (int i = 0; i < sizeof(all_ssh_fn)/sizeof(all_ssh_fn[0]); i++)
  {
    *all_ssh_fn[i].fn = (void *) dlsym(libssh, all_ssh_fn[i].name);
    err_buf = dlerror();
    if (err_buf)
      return err_buf;
  }

  return NULL;
}
