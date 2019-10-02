#define _GNU_SOURCE

#include "nest/bird.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

static _Thread_local int fd = -1;

void cpu_stat_begin(void)
{
  ASSERT(fd >= 0);
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

u64 cpu_stat_end(void)
{
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  u64 out;
  read(fd, &out, sizeof(out));
  return out;
}

static _Thread_local struct perf_event_attr pe;

void cpu_stat_init(void)
{
  pe = (struct perf_event_attr) {
    .type = PERF_TYPE_HARDWARE,
    .size = sizeof(struct perf_event_attr),
    .config = PERF_COUNT_HW_INSTRUCTIONS,
    .disabled = 1,
    .exclude_kernel = 1,
    .exclude_hv = 1,
  };
  
  fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd == -1)
    bug("Error opening perf reader %llx: %m\n", pe.config);
}

void cpu_stat_destroy(void)
{
  close(fd);
}
