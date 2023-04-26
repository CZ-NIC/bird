#!/bin/bash

set -e

LOCAL=2001:db8:dead::

EXTERNAL=2001:db8:beef::
EXTERNAL_NET=${EXTERNAL}/48
EXTERNAL_NH=${LOCAL}beef

LEARN=2001:db8:feed::
LEARN_NET=${LEARN}/48
LEARN_NH=${LOCAL}feed

IFACE=bird-test-dummy
IFACE_EXISTS=false

BIRD_RUNNING=false

D=$(mktemp -d)
pushd ${D} >/dev/null

stop_bird() {
  birdc -l down >/dev/null
  sleep 1
  grep -q "<FATAL> Shutdown completed" bird.log
  [ ! -e bird.pid ]
  [ ! -e bird.ctl ]
}

cleanup() {
  if ${BIRD_RUNNING}; then
    stop_bird
    if [ -e bird.pid ]; then
      kill -9 $(<bird.pid)
    fi
  fi

  if ${IFACE_EXISTS}; then
    ip link del ${IFACE}
  fi


  popd > /dev/null
  rm -rf ${D}
}

failed() {
  cleanup
  exit 1
}

trap failed ERR
trap failed INT
trap failed HUP

ip link add ${IFACE} type dummy
IFACE_EXISTS=true

ip link set ${IFACE} up
ip -6 addr add ${LOCAL}/64 dev bird-test-dummy

ip -6 route add ${LEARN_NET} via ${LEARN_NH}

cat >bird.conf <<EOF
log "bird.log" all;

protocol device {}

protocol kernel {
  ipv6 { import all; export all; };
  learn;
}

protocol static {
  ipv6;
  route ${EXTERNAL_NET} via ${EXTERNAL_NH};
}
EOF

bird -l -P bird.pid

if [ ! -S bird.ctl ] || [ ! -f bird.pid ] || [ ! -f bird.log ]; then
  failed
fi

BIRD_RUNNING=true

ROUTE_INSERTED=false
for _ in $(seq 10); do
  if ip -6 route show ${EXTERNAL_NET} | egrep -q "${EXTERNAL_NET} via ${EXTERNAL_NH} dev ${IFACE} proto bird metric [0-9]+ pref medium"; then
      ROUTE_INSERTED=true
      break
  fi
  sleep 1
done

$ROUTE_INSERTED || failed

if birdc -l show route "${LEARN_NET}" | egrep -q "Network not found"; then
  failed
fi

cleanup
exit 0
