src := cli.c cmds.c iface.c locks.c neighbor.c password.c proto.c proto-build.c rt-attr.c rt-dev.c rt-fib.c rt-show.c rt-table.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,dev_build)

$(proto-build-c): $(lastword $(MAKEFILE_LIST))
	$(E)echo GEN $@
	$(Q)echo "#include \"lib/birdlib.h\"\n$(patsubst %,void %(void);\n,$(PROTO_BUILD)) void protos_build_gen(void) { $(patsubst %,  %();\n,$(PROTO_BUILD))}" > $@

tests_src :=
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
