/*
 *	BIRD -- Benchmarking Dummy Protocol
 *
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PERF_H_
#define _BIRD_PERF_H_

enum perf_mode {
  PERF_MODE_IMPORT,
  PERF_MODE_EXPORT,
};

struct perf_config {
  struct proto_config p;
  btime threshold_min;
  btime threshold_max;
  uint from;
  uint to;
  uint repeat;
  uint keep;
  uint attrs_per_rte;
  enum perf_mode mode;
};

struct perf_proto {
  struct proto p;
  struct ifa *ifa;
  void *data;
  event *loop;
  btime threshold_min;
  btime threshold_max;
  uint from;
  uint to;
  uint repeat;
  uint run;
  uint exp;
  uint stop;
  uint keep;
  uint attrs_per_rte;
  enum perf_mode mode;
};

#endif
