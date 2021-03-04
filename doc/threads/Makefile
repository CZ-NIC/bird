SUFFICES := .pdf -wordpress.html
CHAPTERS := 00_the_name_of_the_game 01_the_route_and_its_attributes 02_asynchronous_export

all: $(foreach ch,$(CHAPTERS),$(addprefix $(ch),$(SUFFICES)))

00_the_name_of_the_game.pdf: 00_filter_structure.png

%.pdf: %.md
	pandoc -f markdown -t latex -o $@ $<

%.html: %.md
	pandoc -f markdown -t html5 -o $@ $<

%-wordpress.html: %.html Makefile
	sed -r 's#</p>#\n#g; s#<p>##g; s#<(/?)code>#<\1tt>#g; s#<pre><tt>#<code>#g; s#</tt></pre>#</code>#g; s#</?figure>##g; s#<figcaption>#<p style="text-align: center">#; s#</figcaption>#</p>#; ' $< > $@
