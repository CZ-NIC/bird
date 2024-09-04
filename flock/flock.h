#define _GNU_SOURCE

#ifndef INCLUDE_FLOCK_H
#define INCLUDE_FLOCK_H
#include "lib/birdlib.h"

void hypervisor_exposed_fork(void);
void hypervisor_control_socket(void);

struct flock_config {
  const char *hypervisor_name;
  const char *exec_name;
  const char *control_socket_path;
};

extern struct flock_config flock_config;

#endif
