INCLUDES = -I. -I$(srcdir) -I$(top_builddir)/gwlib -I$(top_srcdir)/gwlib -I$(top_builddir) -I$(top_srcdir)

lib_LTLIBRARIES = libgw.la
libgw_la_SOURCES = \
	dlr.c \
	dlr_mem.c \
	dlr_mysql.c \
	dlr_oracle.c \
	dlr_pgsql.c \
	dlr_sdb.c \
	heartbeat.c \
	html.c \
	msg.c \
	numhash.c \
	ota_compiler.c \
	ota_prov.c \
	shared.c \
	sms.c \
	urltrans.c \
	xml_shared.c \
	alt_charsets.h \
	dlr.h \
	dlr_p.h \
	heartbeat.h \
	html.h \
	msg-decl.h \
	msg.h \
	numhash.h \
	ota_compiler.h \
	ota_prov_attr.h \
	ota_prov.h \
	shared.h \
	smscconn.h \
	smscconn_p.h \
	sms.h \
	urltrans.h \
	wml_compiler.h \
	wml_definitions.h \
	xml_definitions.h \
	xml_shared.h

sbin_PROGRAMS = bearerbox wapbox smsbox

bearerbox_LDADD = ../gwlib/libgwlib.la libgw.la 
wapbox_LDADD = ../gwlib/libgwlib.la libgw.la ../wap/libwap.la ../radius/libradius.la ../wmlscript/libwmlscript.la
smsbox_LDADD = ../gwlib/libgwlib.la libgw.la ../wap/libwap.la

bearerbox_SOURCES = \
	bearerbox.c \
	bb_alog.c \
	bb_boxc.c \
	bb_http.c \
	bb_smscconn.c \
	bb_store.c \
	bb_udp.c \
	bb_smscconn_cb.h \
	bearerbox.h \
	bb.h \
	smscconn.c \
	smsc/emimsg.c \
	smsc/smasi_pdu.c \
	smsc/smpp_pdu.c \
	smsc/smsc_at.c \
	smsc/smsc.c \
	smsc/smsc_cgw.c \
	smsc/smsc_cimd2.c \
	smsc/smsc_cimd.c \
	smsc/smsc_emi.c \
	smsc/smsc_emi_x25.c \
	smsc/smsc_fake.c \
	smsc/smsc_http.c \
	smsc/smsc_ois.c \
	smsc/smsc_oisd.c \
	smsc/smsc_sema.c \
	smsc/smsc_smasi.c \
	smsc/smsc_smpp.c \
	smsc/smsc_soap.c \
	smsc/smsc_wrapper.c \
	smsc/emimsg.h \
	smsc/smasi_pdu.h \
	smsc/smpp_pdu.h \
	smsc/smsc_at.h \
	smsc/smsc.h \
	smsc/smsc_p.h \
	smsc/smsc_sema.h \
	smsc/smasi_pdu.def \
	smsc/smpp_pdu.def \
	smsc/smpp_pdu_opt.def

wapbox_SOURCES = \
	wapbox.c \
	wap-appl.c \
	wap-appl.h \
	mime_decompiler.c \
	wap-error.c \
	wap-maps.c \
	wap_push_ota.c \
	wap_push_pap_compiler.c \
	wap_push_pap_mime.c \
	wap_push_ppg.c \
	wap_push_ppg_pushuser.c \
	wap_push_si_compiler.c \
	wap_push_sl_compiler.c \
	wml_compiler.c \
	wml_compiler.h \
	wml_definitions.h \
	mime_decompiler.h \
	wap-error.h \
	wap-maps.h \
	wap_push_ota.h \
	wap_push_pap_compiler.h \
	wap_push_pap_mime.h \
	wap_push_ppg.h \
	wap_push_ppg_pushuser.h \
	wap_push_si_compiler.h \
	wap_push_sl_compiler.h \
	wap_ppg_push_machine.def \
	wap_ppg_session_machine.def

