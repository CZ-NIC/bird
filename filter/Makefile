src := filter.c data.c f-util.c tree.c trie.c inst-gen.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

$(conf-y-targets) $(conf-lex-targets) $(src-o-files): $(o)inst-gen.h

M4FLAGS_FILTERS=$(filter-out -s,$(M4FLAGS))

$(o)f-inst-postfixify.c: $(s)postfixify.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -P $^ >$@

$(o)f-inst-interpret.c: $(s)interpret.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -P $^ >$@

$(o)f-inst-same.c: $(s)same.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -P $^ >$@

$(o)inst-gen.h: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -DTARGET=H -P $^ >$@

$(o)inst-gen.c: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -DTARGET=C -P $^ >$@

$(o)filter.o: $(o)f-inst-interpret.c $(o)f-inst-postfixify.c $(o)f-inst-same.c $(o)inst-gen.h

tests_src := tree_test.c filter_test.c trie_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)

$(call clean,inst-gen.h inst-gen.c)
