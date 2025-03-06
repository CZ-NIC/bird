src := iface.c neighbor.c
obj := $(src-o-files)
$(all-lib)

src := cli.c cmds.c iface-cli.c locks.c mpls.c password.c proto.c proto-build.c rt-attr.c rt-dev.c rt-export.c rt-fib.c rt-show.c rt-table.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(conf-y-targets): $(s)mpls.Y

$(o)proto-build.c: Makefile $(lastword $(MAKEFILE_LIST)) $(objdir)/.dir-stamp
	$(E)echo GEN $@
	$(Q)echo "#include \"lib/birdlib.h\"" > $@
	$(Q)$(patsubst %,echo 'void %_build(void);' >> $@;,$(PROTO_BUILD))
	$(Q)echo "void protos_build_gen(void) {" >> $@
	$(Q)$(patsubst %,echo '  %_build();'>>$@;,$(PROTO_BUILD))
	$(Q)echo "}" >> $@

prepare: $(o)proto-build.c

tests_src := rt-fib_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
