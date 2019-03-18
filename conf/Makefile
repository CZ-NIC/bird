src := cf-parse.tab.c cf-lex.c conf.c
obj := $(src-o-files)

$(all-daemon)

tests_objs := $(tests_objs) $(src-o-files)

ifdef DEBUG
BISON_DEBUG=-t
#FLEX_DEBUG=-d
endif

$(o)cf-parse.y: $(s)gen_parser.m4
$(o)keywords.h: $(s)gen_keywords.m4
$(o)commands.h: $(s)gen_commands.m4

$(conf-y-targets): $(s)confbase.Y $(s)flowspec.Y
	$(M4) $(M4FLAGS) -P $(if $(word 2,$(filter %.m4,$^)),$(error "Too many M4 scripts for one target"),$(filter %.m4,$^)) $(filter %.Y,$^) >$@

$(o)cf-parse.tab.h: $(o)cf-parse.tab.c

$(o)cf-parse.tab.c: $(o)cf-parse.y
	$(BISON) $(BISON_DEBUG) $(BISONFLAGS) -dv -pcf_ -b $(@:.tab.c=) $<

$(o)cf-lex.c: $(s)cf-lex.l
	$(FLEX) $(FLEX_DEBUG) -f -s -B -8 -Pcf_ -o$@ $<

$(o)cf-lex.o: CFLAGS+=-Wno-sign-compare -Wno-unused-function

prepare: $(o)keywords.h $(o)commands.h $(o)cf-parse.tab.h

$(addprefix $(o), cf-parse.y keywords.h commands.h cf-parse.tab.h cf-parse.tab.c cf-lex.c): $(objdir)/.dir-stamp

$(call clean,cf-parse.tab.h cf-parse.tab.c cf-parse.y keywords.h commands.h cf-lex.c cf-parse.output)
