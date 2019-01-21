src := filter.c f-util.c tree.c trie.c f-inst-new.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

$(o)f-inst-line-size.c: $(s)line-size.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)f-inst-postfixify.c: $(s)postfixify.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)f-inst-interpret.c: $(s)interpret.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)f-inst-same.c: $(s)same.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)f-inst-struct.h: $(s)struct.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)f-inst-new.c: $(s)new.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)f-inst-dump.c: $(s)dump.m4 $(s)f-inst.c $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS) -P $^ >$@

$(o)filter.o: $(o)f-inst-interpret.c $(o)f-inst-line-size.c $(o)f-inst-postfixify.c $(o)f-inst-same.c $(o)f-inst-dump.c $(o)f-inst-struct.h

tests_src := tree_test.c filter_test.c trie_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
