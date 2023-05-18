from BIRD import Config
from BIRD.Config import DeviceProtocolConfig

cf = Config()
cf.add(DeviceProtocolConfig(name="foo", scan_time=42))
cf.write("test.conf")

