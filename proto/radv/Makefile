src := packets.c radv.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,radv_build)

tests_objs := $(tests_objs) $(src-o-files)
