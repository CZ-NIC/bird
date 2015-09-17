/*
 *	BIRD -- Mockup headers of SSH Library for loading LibSSH using dlopen
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of SSH Library: http://www.libssh.org/
 *	(c) 2003-2009 by Aris Adamantiadis (SSH Library)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIBSSH_H_
#define _BIRD_LIBSSH_H_

#include <unistd.h>
#include <inttypes.h>

typedef struct ssh_session_struct* ssh_session;
typedef struct ssh_channel_struct* ssh_channel;

/* Error return codes */
#define SSH_OK 0     /* No error */
#define SSH_ERROR -1 /* Error of some kind */
#define SSH_AGAIN -2 /* The nonblocking call must be repeated */
#define SSH_EOF -127 /* We have already a eof */

enum ssh_server_known_e {
  SSH_SERVER_ERROR=-1,
  SSH_SERVER_NOT_KNOWN=0,
  SSH_SERVER_KNOWN_OK,
  SSH_SERVER_KNOWN_CHANGED,
  SSH_SERVER_FOUND_OTHER,
  SSH_SERVER_FILE_NOT_FOUND
};

enum ssh_auth_e {
  SSH_AUTH_SUCCESS=0,
  SSH_AUTH_DENIED,
  SSH_AUTH_PARTIAL,
  SSH_AUTH_INFO,
  SSH_AUTH_AGAIN,
  SSH_AUTH_ERROR=-1
};

enum ssh_error_types_e {
  SSH_NO_ERROR=0,
  SSH_REQUEST_DENIED,
  SSH_FATAL,
  SSH_EINTR
};

enum ssh_options_e {
  SSH_OPTIONS_HOST,
  SSH_OPTIONS_PORT,
  SSH_OPTIONS_PORT_STR,
  SSH_OPTIONS_FD,
  SSH_OPTIONS_USER,
  SSH_OPTIONS_SSH_DIR,
  SSH_OPTIONS_IDENTITY,
  SSH_OPTIONS_ADD_IDENTITY,
  SSH_OPTIONS_KNOWNHOSTS,
  SSH_OPTIONS_TIMEOUT,
  SSH_OPTIONS_TIMEOUT_USEC,
  SSH_OPTIONS_SSH1,
  SSH_OPTIONS_SSH2,
  SSH_OPTIONS_LOG_VERBOSITY,
  SSH_OPTIONS_LOG_VERBOSITY_STR,
  SSH_OPTIONS_CIPHERS_C_S,
  SSH_OPTIONS_CIPHERS_S_C,
  SSH_OPTIONS_COMPRESSION_C_S,
  SSH_OPTIONS_COMPRESSION_S_C,
  SSH_OPTIONS_PROXYCOMMAND,
  SSH_OPTIONS_BINDADDR,
  SSH_OPTIONS_STRICTHOSTKEYCHECK,
  SSH_OPTIONS_COMPRESSION,
  SSH_OPTIONS_COMPRESSION_LEVEL,
  SSH_OPTIONS_KEY_EXCHANGE,
  SSH_OPTIONS_HOSTKEYS,
  SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
  SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
  SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
  SSH_OPTIONS_HMAC_C_S,
  SSH_OPTIONS_HMAC_S_C,
};

enum {
  /** No logging at all
   */
  SSH_LOG_NOLOG=0,
  /** Only warnings
   */
  SSH_LOG_WARNING,
  /** High level protocol information
   */
  SSH_LOG_PROTOCOL,
  /** Lower level protocol infomations, packet level
   */
  SSH_LOG_PACKET,
  /** Every function path
   */
  SSH_LOG_FUNCTIONS
};

#ifndef socket_t
typedef int socket_t;
#endif

extern ssh_session (*ssh_new)(void);
extern void (*ssh_set_blocking)(ssh_session session, int blocking);
extern int (*ssh_options_set)(ssh_session session, enum ssh_options_e type, const void *value);
extern int (*ssh_connect)(ssh_session session);
extern socket_t (*ssh_get_fd)(ssh_session session);
extern int (*ssh_is_server_known)(ssh_session session);
extern int (*ssh_userauth_publickey_auto)(ssh_session session, const char *username, const char *passphrase);
extern const char * (*ssh_get_error)(void *error);
extern int (*ssh_get_error_code)(void *error);
extern void (*ssh_disconnect)(ssh_session session);
extern void (*ssh_free)(ssh_session session);

extern ssh_channel (*ssh_channel_new)(ssh_session session);
extern int (*ssh_channel_is_open)(ssh_channel channel);
extern int (*ssh_channel_close)(ssh_channel channel);
extern void (*ssh_channel_free)(ssh_channel channel);
extern int (*ssh_channel_open_session)(ssh_channel channel);
extern int (*ssh_channel_request_subsystem)(ssh_channel channel, const char *subsystem);
extern int (*ssh_channel_read_nonblocking)(ssh_channel channel, void *dest, uint32_t count, int is_stderr);
extern int (*ssh_channel_is_eof)(ssh_channel channel);
extern int (*ssh_channel_select)(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, struct timeval * timeout);
extern int (*ssh_channel_write)(ssh_channel channel, const void *data, uint32_t len);

const char *load_libssh(void);

#endif /* _BIRD_LIBSSH_H_ */
