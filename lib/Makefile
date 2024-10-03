src := bitmap.c bitops.c blake2s.c blake2b.c cbor.c cbor-parser.c cbor_parse_tools.c cbor_shortcuts.c checksum.c defer.c event.c flowspec.c idm.c ip.c lists.c lockfree.c mac.c md5.c mempool.c net.c netindex.c patmatch.c printf.c rcu.c resource.c runtime.c sha1.c sha256.c sha512.c slab.c slists.c strtoul.c tbf.c timer.c xmalloc.c
obj := $(src-o-files)
$(all-lib)

src := a-path.c a-set.c
obj := $(src-o-files)
$(all-daemon)

tests_src := a-set_test.c a-path_test.c attribute_cleanup_test.c bitmap_test.c cbor_test.c heap_test.c buffer_test.c event_test.c flowspec_test.c bitops_test.c patmatch_test.c fletcher16_test.c slist_test.c rt-normalize_test.c checksum_test.c lists_test.c locking_test.c mac_test.c ip_test.c hash_test.c printf_test.c rcu_test.c slab_test.c tlists_test.c type_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
