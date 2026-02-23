#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This is a usage example of aiocoap that demonstrates how to implement a
simple client. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import logging
import asyncio
import cbor2
import io

from aiocoap import Context, Message, GET, POST
from aiocoap.util import linkformat

logging.basicConfig(level=logging.INFO)

class Encoder(cbor2.CBOREncoder):
    def __init__(self):
        self.buf = io.BytesIO()
        super().__init__(fp=self.buf)

cbe = Encoder()

async def main():
    protocol = await Context.create_client_context()

    request = Message(code=GET, uri="coap+tcp://localhost/.well-known/core?rt=core.c.yl&meow")

    try:
        response = await protocol.request(request).response
    except Exception as e:
        print("Failed to fetch resource:")
        print(e)
        exit(1)

    print("Result: %s\n%r" % (response.code, response.payload))
    lf = linkformat.parse(response.payload.decode()).links_by_attr_pairs([])
    print(lf)

    rpc_showmem = cbe.encode_to_bytes({60001: None })
    print(rpc_showmem)

    request = Message(code=POST, uri="coap+tcp://localhost/c", payload=rpc_showmem)

    try:
        response = await protocol.request(request).response
    except Exception as e:
        print("Failed to run RPC:")
        print(e)
        exit(1)

    print("Result: %s\n%r" % (response.code, response.payload))
    print(cbor2.loads(response.payload))


if __name__ == "__main__":
    asyncio.run(main())
