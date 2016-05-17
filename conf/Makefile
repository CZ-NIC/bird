src := cf-parse.tab.c cf-lex.c conf.c
obj := $(src-o-files)

$(all-daemon)

ifdef DEBUG
BISON_DEBUG=-t
#FLEX_DEBUG=-d
endif

$(conf-y-targets): $(s)confbase.Y
	$(M4) -P $| $^ >$@

$(o)cf-parse.y: | $(s)gen_parser.m4
$(o)keywords.h: | $(s)gen_keywords.m4
$(o)commands.h: | $(s)gen_commands.m4 $(srcdir)/client/cmds.m4

$(o)cf-parse.tab.h: $(o)cf-parse.tab.c

$(o)cf-parse.tab.c: $(o)cf-parse.y
	$(BISON) $(BISON_DEBUG) -dv -pcf_ -b $(@:.tab.c=) $<

$(o)cf-lex.c: $(s)cf-lex.l
	$(FLEX) $(FLEX_DEBUG) -s -B -8 -Pcf_ -o$@ $<

$(o)cf-lex.o: $(o)cf-parse.tab.h $(o)keywords.h

$(addprefix $(o), cf-parse.y keywords.h commands.h cf-parse.tab.h cf-parse.tab.c cf-lex.c): $(objdir)/.dir-stamp

$(call clean,cf-parse.tab.h cf-parse.tab.c cf-parse.y keywords.h commands.h cf-lex.c cf-parse.output)
