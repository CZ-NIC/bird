src := validate.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

validate_tmp.o: ../../../../proto/bgp/bgpsec/validate.c
	gcc -c $(CFLAGS) -DLOG_TO_STDERR -o $@ $<

tests: tests.o validate_tmp.o
	gcc -o $@ $^ bgpsec.o $(LDFLAGS) $(LIBS)
