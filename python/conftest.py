from BIRD import Config
from BIRD.Config import DeviceProtocolConfig

cf = Config()
cf.add(dev := DeviceProtocolConfig(name="foo", comment="my own device protocol"))
dev.set("scan_time", 86400, comment="once a day, my interfaces never change")
#cf.add(DeviceProtocolConfig(name="foo", scan_time=42, comment="my own device protocol"))
cf.write("test.conf")

