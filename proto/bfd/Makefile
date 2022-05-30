src := bfd.c io.c packets.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,bfd_build)

tests_objs := $(tests_objs) $(src-o-files)
