src := commands.c util.c client.c log.c print_cbor.c
obj := $(src-o-files)

$(all-client)
$(conf-y-targets): $(s)cmds.Y

$(exedir)/birdc: $(o)birdc.o
# see file nest/Makefile for more $(exedir)/birdc deps
# these are: cbor.o cbor_parse.o cbor_cmds.o
$(exedir)/birdc: LIBS += $(CLIENT_LIBS)

$(exedir)/birdcl: $(o)birdcl.o
# see file nest/Makefile for more $(exedir)/birdcl deps
# these are: cbor.o cbor_parse.o cbor_cmds.o
