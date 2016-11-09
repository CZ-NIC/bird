src := filter.c f-util.c tree.c trie.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

tests_src := tree_test.c filter_test.c trie_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
