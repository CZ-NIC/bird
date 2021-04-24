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
	cp $< $@

$(o)%.html: $(o)%.sgml
	cd $(dir $@) && $(toolsdir)/linuxdoc -B html $(notdir $<)

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
