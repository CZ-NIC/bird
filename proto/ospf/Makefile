src := dbdes.c hello.c iface.c lsack.c lsalib.c lsreq.c lsupd.c neighbor.c ospf.c packet.c rt.c topology.c ospf_for_cbor.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

#$(exedir)/birdc: $(obj)
#$(exedir)/birdcl: $(obj)
#$(exedir)/birdc: $(o)ospf_for_cbor.o $(o)lsalib.o $(o)ospf.o $(o)topology.o \
#  $(o)lsupd.o $(o)neighbor.o $(o)lsack.o $(o)packet.o
#$(exedir)/birdcl: $(o)ospf_for_cbor.o $(o)lsalib.o $(o)ospf.o $(o)topology.o \
#  $(o)lsupd.o $(o)neighbor.o $(o)lsack.o $(o)packet.o

tests_objs := $(tests_objs) $(src-o-files)
