from BIRD.Protocol import Protocol, ProtocolList

class RAdvProtocol(Protocol):
    match = "RAdv"

ProtocolList.register(RAdvProtocol)
