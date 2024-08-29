#define _GNU_SOURCE

#ifndef INCLUDE_FLOCK_H
#define INCLUDE_FLOCK_H
#include "lib/birdlib.h"

void hypervisor_exposed_fork(void);

struct flock_config {
  const char *hypervisor_name;
  const char *exec_name;
};

extern struct flock_config flock_config;

#endif
