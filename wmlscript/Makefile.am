INCLUDES = -I. -I$(srcdir) -I$(top_builddir)/gwlib -I$(top_srcdir)/gwlib -I$(top_builddir) -I$(top_srcdir)

lib_LTLIBRARIES = libwmlscript.la
bin_PROGRAMS = wmlsc wmlsdasm
AM_YFLAGS = -d
wmlsc_LDADD = libwmlscript.la ../gwlib/libgwlib.la
wmlsdasm_LDADD = libwmlscript.la ../gwlib/libgwlib.la
libwmlscript_la_SOURCES = \
	wsalloc.c \
	wsasm.c \
	wsbc.c \
	wsbuffer.c \
	ws.c \
	wsencode.c \
	wserror.c \
	wsfalloc.c \
	wshash.c \
	wsieee754.c \
	wslexer.c \
	wsopt.c \
	wsstdlib.c \
	wsstream.c \
	wsstream_data.c \
	wsstream_file.c \
	wsstree.c \
	wsutf8.c \
	wsalloc.h \
	wsasm.h \
	wsbc.h \
	wsbuffer.h \
	wsencode.h \
	wserror.h \
	wsfalloc.h \
	wsgram.h \
	ws.h \
	wshash.h \
	wsieee754.h \
	wsint.h \
	wsopcodes.h \
	wsopt.h \
	wsstdlib.h \
	wsstream.h \
	wsstree.h \
	wsutf8.h \
	wsgram.y

BUILT_SOURCES = wsopcodes.h

dist_noinst_SCRIPTS = make-op-table.pl
dist_noinst_DATA = lexer.txt

wsopcodes.h: make-op-table.pl wsasm.h
	$(PERL) $(srcdir)/make-op-table.pl $(srcdir)/wsasm.h \
		> $(srcdir)/wsopcodes.h

