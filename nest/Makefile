src := a-path.c a-set.c cli.c cmds.c iface.c locks.c neighbor.c password.c proto.c proto-build.c rt-attr.c rt-dev.c rt-fib.c rt-show.c rt-table.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

$(o)proto-build.c: Makefile $(lastword $(MAKEFILE_LIST)) $(objdir)/.dir-stamp
	$(E)echo GEN $@
	$(Q)echo "\n $(patsubst %, void %_build(void);\n,$(PROTO_BUILD))\nvoid protos_build_gen(void) {\n $(patsubst %, %_build();\n,$(PROTO_BUILD))}" > $@

prepare: $(o)proto-build.c

tests_src := a-set_test.c a-path_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
