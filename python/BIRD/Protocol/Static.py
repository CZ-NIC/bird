from BIRD.Protocol import Protocol, ProtocolList

class StaticProtocol(Protocol):
    match = "Static"

ProtocolList.register(StaticProtocol)
