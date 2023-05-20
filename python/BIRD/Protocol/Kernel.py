from BIRD.Protocol import Protocol, ProtocolList

class DeviceProtocol(Protocol):
    match = "Device"

ProtocolList.register(DeviceProtocol)

class DirectProtocol(Protocol):
    match = "Direct"

ProtocolList.register(DirectProtocol)

class KernelProtocol(Protocol):
    match = "Kernel"

ProtocolList.register(KernelProtocol)
