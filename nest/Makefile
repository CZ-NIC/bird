src := a-path.c a-set.c cli.c cmds.c iface.c locks.c mpls.c neighbor.c password.c proto.c proto-build.c rt-attr.c rt-dev.c rt-fib.c rt-show.c rt-table.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(conf-y-targets): $(s)mpls.Y

$(o)proto-build.c: Makefile $(lastword $(MAKEFILE_LIST)) $(objdir)/.dir-stamp
	$(E)echo GEN $@
	$(Q)( P='$(PROTO_BUILD)' && printf "void %s_build(void);\n" $$P && printf "\nvoid\nprotos_build_gen(void)\n{\n" && printf "  %s_build();\n" $$P && printf "}\n" ) > $@

prepare: $(o)proto-build.c

tests_src := a-set_test.c a-path_test.c rt-fib_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
