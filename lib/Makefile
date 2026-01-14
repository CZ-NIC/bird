src := bitmap.c bitops.c blake2s.c blake2b.c checksum.c event.c flowspec.c idm.c ip.c lists.c mac.c md5.c mempool.c net.c patmatch.c printf.c resource.c sha1.c sha256.c sha512.c slab.c slists.c strtoul.c tbf.c timer.c xmalloc.c
obj := $(src-o-files) $(o)types.o
$(all-daemon)
$(types-local)

M4FLAGS_TYPES=$(filter-out -s,$(M4FLAGS))
#M4FLAGS_TYPES=$(M4FLAGS)

$(o)types.Y: $(s)types.m4 | $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_TYPES) -DTARGET=Y -P $^ >$@

$(o)types-enums.h: $(s)types.m4 | $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_TYPES) -DTARGET=ENUMS -P $^ >$@

$(o)types-union.h: $(s)types.m4 | $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_TYPES) -DTARGET=UNION -P $^ >$@

$(o)types.c: $(s)types.m4 | $(objdir)/.dir-stamp
	$(M4) $(M4FLAGS_TYPES) -DTARGET=C -P $^ >$@

$(conf-y-targets): $(o)types.Y
prepare: $(o)types-enums.h $(o)types-union.h $(o)types.c

tests_src := bitmap_test.c heap_test.c buffer_test.c event_test.c flowspec_test.c bitops_test.c patmatch_test.c fletcher16_test.c slist_test.c checksum_test.c lists_test.c mac_test.c ip_test.c hash_test.c printf_test.c slab_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files) $(o)types.o

$(call clean,types.Y types-enums.h types-union.h types.c)
