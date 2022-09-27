src := packets.c rip.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,rip_build)

tests_objs := $(tests_objs) $(src-o-files)
