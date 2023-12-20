src := rpki.c packets.c tcp_transport.c ssh_transport.c transport.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

$(exedir)/birdc: $(obj)
$(exedir)/birdcl: $(obj)

tests_objs := $(tests_objs) $(src-o-files)
