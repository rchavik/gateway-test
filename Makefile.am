SUBDIRS = gwlib wmlscript radius wap gw benchmarks utils checks doc test
EXTRA_DIST = contrib VERSION


make-op-table: $(srcdir)/wmlscript/make-op-table.in
	sed 's%@PERLPROG@%@PERL@%g' $(srcdir)/wmlscript/make-op-table.in \
		> make-op-table
	chmod a+x make-op-table

opcodes:
	./make-op-table $(srcdir)/wmlscript/wsasm.h \
		> $(srcdir)/wmlscript/wsopcodes.h

dist-hook:
	rm -rf `find $(distdir) -name CVS -or -name SCCS`

pkg: all
	(cd solaris; mk-solaris-package.sh)
	echo Package is now in solaris directory

gw-config: utils/foobar-config.sh Makefile
	./utils/foobar-config.sh "-I$(includedir)/kannel @CFLAGS@" \
		"-L$(libdir)/kannel -lgwlib @LIBS@" \
		"@GW_VERSION@" > gw-config
	chmod 0755 gw-config

