src := attrs.c bgp.c packets.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,bgp_build)

tests_objs := $(tests_objs) $(src-o-files)
