#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef INCLUDE_FLOCK_H
#define INCLUDE_FLOCK_H
#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/event.h"
#include "lib/obstacle.h"
#include "lib/resource.h"
#include "lib/socket.h"

void hypervisor_container_fork(void);
void hypervisor_exposed_fork(void);
void hypervisor_control_socket(void);

struct flock_config {
  const char *hypervisor_name;
  const char *exec_name;
  const char *control_socket_path;
};

extern struct flock_config flock_config;

struct hcs_parser_context *hcs_parser_init(sock *s);
s64 hcs_parse(struct hcs_parser_context *ctx, const byte *buf, s64 size);
void hcs_parser_cleanup(struct hcs_parser_context *ctx);
const char *hcs_error(struct hcs_parser_context *ctx);
bool hcs_complete(struct hcs_parser_context *ctx);

void hexp_get_telnet(sock *, const char *name);

union flock_machine_config {
  struct flock_machine_common_config {
    const char *name;
    enum {
      FLOCK_MACHINE_NONE = 0,
      FLOCK_MACHINE_CONTAINER = 1,
    } type;
  } cf;
  struct flock_machine_container_config {
    struct flock_machine_common_config cf;
    const char *workdir;
    const char *basedir;
  } container;
};

void hypervisor_container_start(struct cbor_channel *, struct flock_machine_container_config *);
void hypervisor_container_shutdown(struct cbor_channel *, struct flock_machine_container_config *);
int container_ctl_fd(const char *name);

void hexp_cleanup_after_fork(void);

extern event reboot_event, poweroff_event;
extern event_list shutdown_event_list;

extern struct shutdown_placeholder {
  struct obstacle_target obstacles;
} shutdown_placeholder;
#endif
