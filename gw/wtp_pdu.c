/* wtp_pdu.c - pack and unpack WTP packets
 *
 * Generates packing and unpacking code from wtp_pdu.def.
 *
 * Richard Braakman <dark@wapit.com>
 */

#include "gwlib/gwlib.h"
#include "wtp_pdu.h"

WTP_PDU *wtp_pdu_create(int type) {
	WTP_PDU *pdu;
	
	pdu = gw_malloc(sizeof(*pdu));
	pdu->type = type;
	pdu->options = NULL;

	switch (pdu->type) {
#define PDU(name, docstring, fields, is_valid) \
	case name: {\
	struct name *p; p = &pdu->u.name; \
	fields \
	} break;
#define UINT(field, docstring, bits) p->field = 0;
#define UINTVAR(field, docstring) p->field = 0;
#define OCTSTR(field, docstring, lengthfield) p->field = NULL;
#define REST(field, docstring) p->field = NULL;
#define TYPE(bits, value) 
#define RESERVED(bits) 
#define TPI(confield)
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU
	default:
		warning(0, "Cannot destroy unknown WTP PDU type %d", pdu->type);
		break;
	}

	return pdu;
}

void wtp_pdu_destroy(WTP_PDU *pdu) {
	if (pdu == NULL)
		return;

	switch (pdu->type) {
#define PDU(name, docstring, fields, is_valid) \
	case name: {\
	struct name *p; p = &pdu->u.name; \
	fields \
	} break;
#define UINT(field, docstring, bits)
#define UINTVAR(field, docstring)
#define OCTSTR(field, docstring, lengthfield) octstr_destroy(p->field);
#define REST(field, docstring) octstr_destroy(p->field);
#define TYPE(bits, value)
#define RESERVED(bits)
#define TPI(confield)
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU
	default:
		warning(0, "Cannot destroy unknown WTP PDU type %d", pdu->type);
		break;
	}

	if (pdu->options) {
		while (list_len(pdu->options)) {
			wtp_tpi_destroy(list_consume(pdu->options));
		}
		list_destroy(pdu->options);
	}

	gw_free(pdu);
}

void wtp_tpi_destroy(WTP_TPI *p) {
	if (p == NULL)
		return;

	octstr_destroy(p->data);
	gw_free(p);
}

void wtp_pdu_append_tpi(WTP_PDU *pdu, int type, Octstr *data) {
	WTP_TPI *tpi;

	tpi = gw_malloc(sizeof(*tpi));
	tpi->type = type;
	tpi->data = data;
	if (pdu->options == NULL)
		pdu->options = list_create();
	list_append(pdu->options, tpi);
}

static long unpack_tpis(Octstr *data, long bitpos, WTP_PDU *pdu) {
	long length;
	int type;
	Octstr *tpidata;
	int another;

	do {
		another = octstr_get_bits(data, bitpos, 1);
		type = octstr_get_bits(data, bitpos + 1, 4);
		if (octstr_get_bits(data, bitpos + 5, 1)) {
			/* Long TPI */
			length = octstr_get_bits(data, bitpos + 8, 8);
			bitpos += 16;
		} else {
			/* Short TPI */
			length = octstr_get_bits(data, bitpos + 6, 2);
			bitpos += 8;
		}
		gw_assert(bitpos % 8 == 0);
		tpidata = octstr_copy(data, bitpos / 8, length);
		bitpos += 8 * length;
		wtp_pdu_append_tpi(pdu, type, data);
	} while (another);

	return bitpos;
}

static long pack_tpis(Octstr *data, long bitpos, List *tpis) {
	long length;
	WTP_TPI *tpi;
	int i;
	int num_tpis;

	num_tpis = list_len(tpis);
	for (i = 0; i < num_tpis; i++) {
		tpi = list_get(tpis, i);
		length = octstr_len(tpi->data);
		octstr_set_bits(data, bitpos, 1, i + 1 < num_tpis);
		octstr_set_bits(data, bitpos + 1, 4, tpi->type);
		if (length >= 4) {
			/* Long TPI */
			octstr_set_bits(data, bitpos + 5, 1, 1);
			octstr_set_bits(data, bitpos + 8, 8, length);
			bitpos += 16;
		} else {
			/* Short TPI */
			octstr_set_bits(data, bitpos + 5, 1, 0);
			octstr_set_bits(data, bitpos + 6, 2, length);
			bitpos += 8;
		}
		gw_assert(bitpos % 8 == 0);
		octstr_append(data, tpi->data);
		bitpos += 8 * length;
	}

	return bitpos;
}

static void dump_tpis(List *tpis, int level) {
	int i;
	int num_tpis;
	WTP_TPI *tpi;

	if (tpis == NULL)
		return;

	num_tpis = list_len(tpis);
	for (i = 0; i < num_tpis; i++) {
		tpi = list_get(tpis, i);
		debug("wap.wtp", 0, "%*s TPI type %u:", level, "", tpi->type);
		octstr_dump(tpi->data, level + 1);
	}
}

/* Determine which type of PDU this is, using the TYPE macros in
 * the definition file. */
static int wtp_pdu_type(Octstr *data) {
	long bitpos;
	long lastpos = -1;
	long lastnumbits = -1;
	long lastval = -1;
	int thistype;

	/* This code looks slow, but an optimizing compiler will
	 * reduce it considerably.  gcc -O2 will produce a single
	 * call to octstr_get_bits, folllowed by a sequence of
	 * tests on lastval. */

/* Only UINT and RESERVED fields may precede the TYPE */
#define PDU(name, docstring, fields, is_valid) \
	bitpos = 0; \
	thistype = name; \
	fields
#define UINT(field, docstring, bits) bitpos += (bits);
#define UINTVAR(field, docstring)
#define OCTSTR(field, docstring, lengthfield)
#define REST(field, docstring)
#define TYPE(bits, value) \
	if ((bits) != lastnumbits || bitpos != lastpos) { \
		lastval = octstr_get_bits(data, bitpos, (bits)); \
	} \
	if (lastval == (value)) \
		return thistype; \
	lastnumbits = (bits); \
	lastpos = bitpos;
#define RESERVED(bits) bitpos += (bits);
#define TPI(confield)
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU

	return -1;
}

WTP_PDU *wtp_pdu_unpack(Octstr *data) {
	WTP_PDU *pdu = NULL;
	long bitpos = 0;

	gw_assert(data != NULL);

	pdu = gw_malloc(sizeof(*pdu));

	pdu->type = wtp_pdu_type(data);
	pdu->options = NULL;

	switch (pdu->type) {
#define PDU(name, docstring, fields, is_valid) \
	case name: { \
		struct name *p = &pdu->u.name; \
		fields \
		gw_assert(bitpos % 8 == 0); \
		if (bitpos / 8 != octstr_len(data)) { \
			warning(0, "Bad length for " #name " PDU, " \
				" expected %ld", bitpos / 8); \
		} \
		if (!(is_valid)) { \
			warning(0, #name " PDU failed %s", #is_valid); \
                        return NULL; \
		} \
	} break;
#define UINT(field, docstring, bits) \
	p->field = octstr_get_bits(data, bitpos, (bits)); \
	bitpos += (bits);
#define UINTVAR(field, docstring) \
	gw_assert(bitpos % 8 == 0); \
	p->field = octstr_get_bits(data, bitpos + 1, 7); \
	while (octstr_get_bits(data, bitpos, 1)) { \
		bitpos += 8; \
		p->field <<= 7; \
		p->field |= octstr_get_bits(data, bitpos + 1, 7); \
	} \
	bitpos += 8;
#define OCTSTR(field, docstring, lengthfield) \
	gw_assert(bitpos % 8 == 0); \
	p->field = octstr_copy(data, bitpos / 8, p->lengthfield); \
	bitpos += 8 * p->lengthfield;
#define REST(field, docstring) \
	gw_assert(bitpos % 8 == 0); \
	if (bitpos / 8 <= octstr_len(data)) { \
		p->field = octstr_copy(data, bitpos / 8, \
				octstr_len(data) - bitpos / 8); \
		bitpos = octstr_len(data) * 8; \
	}
#define TYPE(bits, value) bitpos += (bits);
#define RESERVED(bits) bitpos += (bits);
#define TPI(confield) \
	if (p->confield) { \
		pdu->options = list_create(); \
		bitpos = unpack_tpis(data, bitpos, pdu); \
	}
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU
	default:
		warning(0, "WTP PDU with unknown type %d", pdu->type);
		gw_free(pdu);
		return NULL;
	}

	return pdu;
}

static void fixup_length_fields(WTP_PDU *pdu) {
	switch (pdu->type) {
#define PDU(name, docstring, fields, is_valid) \
	case name: { \
		struct name *p = &pdu->u.name; \
		fields \
	} break;
#define UINT(field, docstring, bits)
#define UINTVAR(field, docstring)
#define OCTSTR(field, docstring, lengthfield) \
	p->lengthfield = octstr_len(p->field);
#define REST(field, docstring)
#define TYPE(bits, value)
#define RESERVED(bits)
#define TPI(confield) \
	p->confield = pdu->options != NULL && list_len(pdu->options) > 0;
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU
	}
}

Octstr *wtp_pdu_pack(WTP_PDU *pdu) {
	Octstr *data;
	long bitpos;

	/* We rely on octstr_set_bits to lengthen our octstr as needed. */
	data = octstr_create_empty();

	fixup_length_fields(pdu);

	bitpos = 0;
	switch (pdu->type) {
#define PDU(name, docstring, fields, is_valid) \
	case name: { \
		struct name *p = &pdu->u.name; \
		fields \
		gw_assert(bitpos % 8 == 0); \
	} break;
#define UINT(field, docstring, bits) \
	octstr_set_bits(data, bitpos, (bits), p->field); \
	bitpos += (bits);
#define UINTVAR(field, docstring) \
	gw_assert(bitpos % 8 == 0); \
	octstr_append_uintvar(data, p->field); \
	bitpos = 8 * octstr_len(data);
#define OCTSTR(field, docstring, lengthfield) \
	gw_assert(bitpos % 8 == 0); \
	if (p->field != NULL) \
		octstr_append(data, p->field); \
	bitpos += 8 * octstr_len(p->field);
#define REST(field, docstring) \
	gw_assert(bitpos % 8 == 0); \
	if (p->field != NULL) \
		octstr_append(data, p->field); \
	bitpos += 8 * octstr_len(p->field);
#define TYPE(bits, value) \
	octstr_set_bits(data, bitpos, (bits), (value)); \
	bitpos += (bits);
#define RESERVED(bits) bitpos += (bits);
#define TPI(confield) \
	if (p->confield) { \
		bitpos = pack_tpis(data, bitpos, pdu->options); \
	}
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU
	default:
		panic(0, "Packing unknown WTP PDU type %ld", (long) pdu->type);
	}

	return data;
}

void wtp_pdu_dump(WTP_PDU *pdu, int level) {
	unsigned char *dbg = "wap.wtp";

	switch (pdu->type) {
#define PDU(name, docstring, fields, is_valid) \
	case name: { \
		struct name *p = &pdu->u.name; \
		debug(dbg, 0, "%*sWTP %s PDU at %p:", \
			level, "", #name, (void *)pdu); \
		fields \
	} break;
#define UINT(field, docstring, bits) \
	debug(dbg, 0, "%*s %s: %lu", level, "", docstring, p->field);
#define UINTVAR(field, docstring) \
	debug(dbg, 0, "%*s %s: %lu", level, "", docstring, p->field);
#define OCTSTR(field, docstring, lengthfield) \
	debug(dbg, 0, "%*s %s:", level, "", docstring); \
	octstr_dump(p->field, level + 1);
#define REST(field, docstring) \
	debug(dbg, 0, "%*s %s:", level, "", docstring); \
	octstr_dump(p->field, level + 1);
#define TYPE(bits, value)
#define RESERVED(bits)
#define TPI(confield) dump_tpis(pdu->options, level);
#include "wtp_pdu.def"
#undef TPI
#undef RESERVED
#undef TYPE
#undef REST
#undef OCTSTR
#undef UINTVAR
#undef UINT
#undef PDU
	default:
		debug(dbg, 0, "%*sWTP PDU at %p:", level, "", (void *)pdu);
		debug(dbg, 0, "%*s unknown type %u", level, "", pdu->type);
		break;
	}
}
