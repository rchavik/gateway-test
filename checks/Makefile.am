INCLUDES = -I. -I$(srcdir) -I$(top_builddir)/gwlib -I$(top_srcdir)/gwlib -I$(top_builddir) -I$(top_srcdir)

noinst_PROGRAMS = \
	check_counter \
	check_date \
	check_ipcheck \
	check_list \
	check_octstr

dist_noinst_SCRIPTS = \
	check_compiler.sh \
	check_fakesmsc.sh \
	check_fakewap.sh \
	check_headers.sh \
	check_http.sh \
	check_httpsmsc_kannel.sh \
	check_ppg.sh \
	check_sendsms.sh \
	check_smpp.sh

dist_noinst_DATA = \
	test_dates

LDADD = ../gwlib/libgwlib.la
