src := filter.c data.c f-util.c tree.c trie.c inst-gen.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

#M4FLAGS_FILTERS=$(filter-out -s,$(M4FLAGS))
M4FLAGS_FILTERS=$(M4FLAGS)

$(o)inst-gen.h: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -DTARGET=H -P $^ >$@

$(o)inst-gen.c: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -DTARGET=C -P $^ >$@

$(o)inst-interpret.c: $(s)decl.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_FILTERS) -DTARGET=I -P $^ >$@

prepare: $(o)inst-interpret.c $(o)inst-gen.h

tests_src := tree_test.c filter_test.c trie_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)

$(call clean,inst-gen.h inst-gen.c inst-interpret.c)
