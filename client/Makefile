src := commands.c util.c client.c
obj := $(src-o-files)

$(all-client)
$(conf-y-targets): $(s)cmds.Y

$(o)commands.o: $(objdir)/conf/commands.h

$(exedir)/birdc: $(o)birdc.o
$(exedir)/birdc: LIBS += $(CLIENT_LIBS)

$(exedir)/birdcl: $(o)birdcl.o
