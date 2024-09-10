#define _GNU_SOURCE

#ifndef INCLUDE_FLOCK_H
#define INCLUDE_FLOCK_H
#include "lib/birdlib.h"
#include "lib/event.h"
#include "lib/obstacle.h"
#include "lib/resource.h"

void hypervisor_exposed_fork(void);
void hypervisor_control_socket(void);

struct flock_config {
  const char *hypervisor_name;
  const char *exec_name;
  const char *control_socket_path;
};

extern struct flock_config flock_config;

struct cbor_parser_context *hcs_parser_init(pool *p);
s64 hcs_parse(struct cbor_parser_context *ctx, const byte *buf, s64 size);
void hcs_parser_cleanup(struct cbor_parser_context *ctx);
const char *hcs_error(struct cbor_parser_context *ctx);
bool hcs_complete(struct cbor_parser_context *ctx);

extern event reboot_event, poweroff_event;
extern event_list shutdown_event_list;

extern struct shutdown_placeholder {
  struct obstacle_target obstacles;
} shutdown_placeholder;
#endif
