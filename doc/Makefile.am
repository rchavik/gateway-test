if BUILD_ALLDOCS
doc_SCRIPTS = userguide/userguide.html
CLEANFILES = userguide/userguide.html
endif


.xml.html:
	mkdir -p `dirname $*.tmp`
	sed "s/#FIGTYPE#/.png/;s/#VERSION#/${VERSION}/;s/#DATE#/`date +%Y.%m.%d`/;s/#DRAFTS#/${DOCDRAFTS}/" $< > $*.tmp
	${JADE} -V nochunks -t sgml -d $(HTML_DSL) $*.tmp > $@
	rm -f $*.tmp

.xml.rtf:
	sed "s/#FIGTYPE#/.ps/;s/#VERSION#/${VERSION}/;s/#DATE#/`date +%Y.%m.%d`/;s/#DRAFTS#/${DOCDRAFTS}/" $< > $*.tmp
	cd `dirname $<` && $(JADE) -o `basename $*`.rtf -t rtf -d $(TEX_DSL) `basename $*`.tmp
	rm -f $*.tmp

.xml.ps:
	sed "s/#FIGTYPE#/.ps/;s/#VERSION#/${VERSION}/;s/#DATE#/`date +%Y.%m.%d`/;s/#DRAFTS#/${DOCDRAFTS}/" $< > $*.tmp
	$(JADE) -o $*.tex -t tex -d $(TEX_DSL) $*.tmp
	rm -f $*.tmp
	cd `dirname $<` && $(JADETEX) `basename $*`.tex >/dev/null || true
	cd `dirname $<` && $(JADETEX) `basename $*`.tex >/dev/null || true
	cd `dirname $<` && $(JADETEX) `basename $*`.tex >/dev/null || \
	( echo Check `dirname $<`/`basename $*`.log for errors && false)
	rm -f $*.log
	cd `dirname $<` && $(DVIPS) -q -o `basename $*`.ps `basename $*`.dvi
	rm -f $*.dvi $*.tex $*.aux

.xml.pdf:
	sed "s/#FIGTYPE#/.png/;s/#VERSION#/${VERSION}/;s/#DATE#/`date +%Y.%m.%d`/;s/#DRAFTS#/${DOCDRAFTS}/" $< > $*.tmp
	$(JADE) -o $*.tex -t tex -d $(TEX_DSL) $*.tmp
	rm -f $*.tmp
	cd `dirname $<` && $(JADETEX) `basename $*`.tex >/dev/null || true
	cd `dirname $<` && $(JADETEX) `basename $*`.tex >/dev/null || true
	cd `dirname $<` && $(JADETEX) `basename $*`.tex >/dev/null || true
	rm -f $*.log $*.dvi
	cd `dirname $<` && $(PDFJADETEX) `basename $*`.tex > /dev/null || true
	test -r $*.pdf || false
	rm -f $*.log $*.tex $*.aux $*.out

.fig.png:
	$(FIG2DEV) -Lpng $< $@

.fig.ps:
	$(FIG2DEV) -Lps $< $@

.png.ps:
	$(CONVERT) $< $@

dist_noinst_DATA = \
	alligata/11-1.png \
	alligata/11-3.png \
	alligata/11-4.png \
	alligata/11-5.png \
	alligata/12-10.png \
	alligata/12-11.png \
	alligata/12-12.png \
	alligata/12-13.png \
	alligata/12-2.png \
	alligata/12-3.png \
	alligata/12-4.png \
	alligata/12-5.png \
	alligata/12-6.png \
	alligata/12-7.png \
	alligata/12-8.png \
	alligata/12-9.png \
	alligata/13-5.png \
	alligata/alligata.xml \
	alligata/done.png \
	alligata/licences.png \
	alligata/maininst.png \
	alligata/nearlydone.png \
	alligata/nopro.png \
	alligata/progress.png \
	alligata/wapdiagsmall.png \
	arch/arch.xml \
	arch/bearerbox-arch.fig \
	arch/conf-push-session.fig \
	arch/external-interfaces.fig \
	arch/kannel-boxes.fig \
	arch/kannel-push-boxes.fig \
	arch/pushbox-threads.fig \
	arch/wap-arch.fig \
	arch/wapbox-threads.fig \
	arch/wap-session.fig \
	ChangeLog-0.13.1 \
	ChangeLog-1.1 \
	ChangeLog-1.1.1 \
	ChangeLog-1.1.2 \
	ChangeLog-1.1.3 \
	ChangeLog-1.1.4 \
	ChangeLog-1.1.5 \
	ChangeLog-1.1.6 \
	ChangeLog-1.2.0 \
	ChangeLog-1.2.1 \
	ChangeLog-1.3.0 \
	ChangeLog-1.3.1 \
	ChangeLog-1.3.2 \
	CodingStyle \
	dialup.txt \
	examples/dlr-mysql.conf \
	examples/dlr-oracle.conf \
	examples/dlr-sdb.conf \
	examples/kannel.conf \
	examples/modems.conf \
	fakewap-packets.txt \
	release.txt \
	userguide/sms-gateway.fig \
	userguide/userguide.xml \
	userguide/wap-gateway.fig \
	wtls/fig10o.png \
	wtls/fig1o.png \
	wtls/fig2o.png \
	wtls/fig3o.png \
	wtls/fig4o.png \
	wtls/fig4out.png \
	wtls/fig5o.png \
	wtls/fig5out.png \
	wtls/fig6o.png \
	wtls/fig6out1.png \
	wtls/fig6out.png \
	wtls/fig7o.png \
	wtls/fig8o.png \
	wtls/fig9o.png \
	wtls/wtls.xml
