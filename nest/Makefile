src := cli.c cmds.c iface.c locks.c neighbor.c password.c proto.c proto-build.c rt-attr.c rt-dev.c rt-fib.c rt-show.c rt-table.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

$(objdir)/nest/proto-build.c: $(lastword $(MAKEFILE_LIST))
	$(E)echo GEN $@
	$(Q)echo "#include \"lib/birdlib.h\"" > $@
	$(Q)$(patsubst %,echo 'void %_build(void);' >> $@;,$(PROTO_BUILD))
	$(Q)echo "void protos_build_gen(void) {" >> $@
	$(Q)$(patsubst %,echo '  %_build();'>>$@;,$(PROTO_BUILD))
	$(Q)echo "}" >> $@

tests_src :=
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
