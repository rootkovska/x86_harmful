TITLE := x86_harmful

all: $(TITLE).pdf $(TITLE).epub

$(TITLE).pdf: $(TITLE).tex
	pdflatex $(TITLE) && \
	bibtex $(TITLE) && \
	pdflatex $(TITLE) && \
	pdflatex $(TITLE)

$(TITLE).tex: $(TITLE).md biblio/*.bib style/template.tex
	pandoc $(TITLE).md \
		-f markdown+footnotes \
		--toc \
		--biblio biblio/qubes.bib \
		--biblio biblio/itl_attacks.bib \
		--biblio biblio/kernel_attacks.bib \
		--biblio biblio/bios_attacks.bib \
		--biblio biblio/hw_mods.bib \
		--biblio biblio/intel_docs.bib \
		--biblio biblio/intel_analysis.bib \
		--biblio biblio/misc.bib \
		--biblio biblio/cover_and_side_channels.bib \
		--natbib \
		--template style/template.tex \
		-V documentclass=report \
		-V papersize=a4paper \
		-V fontsize=12pt \
		-V biblio-style=plain \
		-o $(TITLE).tex

$(TITLE).epub: $(TITLE).md biblio/*.bib
	pandoc $(TITLE).md \
		-f markdown+footnotes \
		--biblio biblio/qubes.bib \
		--biblio biblio/itl_attacks.bib \
		--biblio biblio/kernel_attacks.bib \
		--biblio biblio/bios_attacks.bib \
		--biblio biblio/hw_mods.bib \
		--biblio biblio/intel_docs.bib \
		--biblio biblio/intel_analysis.bib \
		--biblio biblio/misc.bib \
		--biblio biblio/cover_and_side_channels.bib \
		--csl style/ieee.csl \
		-o $(TITLE).epub

clean:
	rm -f $(TITLE).tex $(TITLE).aux $(TITLE).log $(TITLE).toc $(TITLE).bbl $(TITLE).blg $(TITLE).out

clean-all:
	rm -f $(TITLE).pdf $(TITLE).epub
