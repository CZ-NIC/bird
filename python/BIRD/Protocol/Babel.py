from BIRD.Protocol import Protocol, ProtocolList

class BabelProtocol(Protocol):
    match = "Babel"

ProtocolList.register(BabelProtocol)
