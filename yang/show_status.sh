#!/bin/bash

# aiocoap-client is required
# you can get it be running:
#
# pipx install aiocoap
#
# coap-client should have compatible or similar interface
# (part of CoAP library libcoap, libcoap3-bin on debian)
# coap-client-notls, coap-client-openssl

aiocoap-client \
  -m POST \
  --content-format 65001 \
  --payload @status-req.cbor \
  coap+tcp://localhost/c | tee status_out | cbor2 --pretty -

