dist_noinst_SCRIPTS = \
	bench_http.sh \
	bench_sms.sh \
	functions.inc \
	run-benchmarks

dist_noinst_DATA = \
	bench_http.txt \
	bench_sms.conf \
	bench_sms.txt \
	report-begin.txt \
	report-end.txt

benchformats = report.pdf report.ps report.html

report.xml: run-benchmarks
	./run-benchmarks bench_*.sh

bench: $(benchformats)
