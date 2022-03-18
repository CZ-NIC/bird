src := dbdes.c hello.c iface.c lsack.c lsalib.c lsreq.c lsupd.c neighbor.c ospf.c packet.c rt.c topology.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,ospf_build)

tests_objs := $(tests_objs) $(src-o-files)
