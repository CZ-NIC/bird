src := bitops.c checksum.c event.c flowspec.c idm.c ip.c lists.c mac.c md5.c mempool.c net.c patmatch.c printf.c resource.c sha1.c sha256.c sha512.c slab.c slists.c strtoul.c tbf.c timer.c xmalloc.c
obj := $(src-o-files)
$(all-daemon)

tests_src := heap_test.c buffer_test.c event_test.c flowspec_test.c bitops_test.c patmatch_test.c fletcher16_test.c slist_test.c checksum_test.c lists_test.c mac_test.c ip_test.c hash_test.c printf_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
