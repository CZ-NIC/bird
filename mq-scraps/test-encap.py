import cbor2
import json
import ipaddress

print(cbor2.decoder.semantic_decoders)
print(cbor2.decoder.special_decoders)
cbor2.decoder.semantic_decoders[54] = cbor2.decoder.semantic_decoders[260]

def testhook(decoder, value):
    print(value)
    print(value.tag, value.value)
    return {
            24: lambda: value,
            54: lambda: ipaddress.IPv6Address(value.value),
            }[value.tag]()

with open("test-encap.cbor", "rb") as sf:
    dec = cbor2.CBORDecoder(sf, testhook)
    print(data := dec.decode())
    print(data.value[3])
