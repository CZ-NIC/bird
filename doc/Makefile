# Force rebuilds
.PHONY: progspell docs progdocs userdocs

doc-srcdir := $(realpath $(srcdir)/doc)
toolsdir := $(realpath $(srcdir)/tools)

docs: progdocs userdocs

doc-fmt = $(1): $(o)prog.$(1) $(o)bird.$(1)
$(call doc-fmt,html)
$(call doc-fmt,dvi)
$(call doc-fmt,ps)
$(call doc-fmt,pdf)

progdocs: $(o)prog.html $(o)prog.pdf
userdocs: $(o)bird.html $(o)bird.pdf
progspell: $(o)prog.spell

$(o)prog.sgml: $(srcdir)/tools/progdoc $(objdir)/.dir-stamp
	$(srcdir)/tools/progdoc $(srcdir) $@

$(o)%.sgml: $(s)%.sgml $(objdir)/.dir-stamp
	sed 's#{{ VERSION }}#$(VERSION)#' <$< >$@

$(o)%.html: $(o)%.sgml
	cd $(dir $@) && $(toolsdir)/linuxdoc -B html $(notdir $<)

ifeq ($(PANDOC),)
$(o)%.md: $(o)%.sgml
	@echo "ERROR: No pandoc available, install pandoc to build documentation"
	@false
else
LINUXDOC_PANDOC_PARSER := $(srcdir)/tools/linuxdoc.lua
SINGLEPAGE_HTML_TEMPLATE := $(srcdir)/tools/doc-template.html
$(o)%.md: $(o)%.sgml $(LINUXDOC_PANDOC_PARSER) $(objdir)/.dir-stamp
	$(PANDOC) -f $(LINUXDOC_PANDOC_PARSER) -s -t markdown -o $@ $<

$(o)%-singlepage.html: $(o)%.sgml $(SINGLEPAGE_HTML_TEMPLATE) $(LINUXDOC_PANDOC_PARSER) $(objdir)/.dir-stamp
	$(PANDOC) -f $(LINUXDOC_PANDOC_PARSER) -t html5 --shift-heading-level-by=1 --section-divs --table-of-contents --toc-depth=3 -M bird_version="$(VERSION)" --template=$(SINGLEPAGE_HTML_TEMPLATE) -o $@ $<

endif

$(o)%.tex: $(o)%.sgml
	cd $(dir $@) && $(toolsdir)/linuxdoc -B latex --output=tex $(notdir $<)

$(o)%.dvi: $(o)%.tex
	cd $(dir $@) && TEXINPUTS=$(TEXINPUTS):$(doc-srcdir)/tex latex $(notdir $<)
	cd $(dir $@) && TEXINPUTS=$(TEXINPUTS):$(doc-srcdir)/tex latex $(notdir $<)

$(o)%.ps: $(o)%.dvi
	dvips -D600 -ta4 -o $@ $<

$(o)%.pdf: $(o)%.tex
	TEXINPUTS=$(TEXINPUTS):$(doc-srcdir)/tex pdflatex -output-directory=$(dir $@) $<
	TEXINPUTS=$(TEXINPUTS):$(doc-srcdir)/tex pdflatex -output-directory=$(dir $@) $<

$(o)%.txt: $(o)%.sgml
	cd $(dir $@) && $(toolsdir)/linuxdoc -B txt $(notdir $<)

$(o)prog.spell: $(o)prog.sgml $(s)prog-spell.sed
	sed -f $(lastword $^) <$< >$@
	ispell $@

$(call clean,prog.spell $(addprefix *.,html dvi ps pdf sgml tex txt aux log toc))
