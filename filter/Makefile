src := filter.c data.c f-util.c tree.c trie.c inst-gen.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

$(conf-y-targets) $(conf-lex-targets) $(src-o-files): $(o)inst-gen.h

$(o)inst-gen.h: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -DTARGET=H -P $^ >$@

$(o)inst-gen.c: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -DTARGET=C -P $^ >$@

$(o)inst-interpret.c: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -DTARGET=I -P $^ >$@

$(o)filter.o: $(o)inst-interpret.c $(o)inst-gen.h

tests_src := tree_test.c filter_test.c trie_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)

$(call clean,inst-gen.h inst-gen.c)
