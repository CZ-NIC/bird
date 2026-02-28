src := commands.c util.c client.c
obj := $(src-o-files)

$(all-client)
$(conf-y-targets): $(s)cmds.Y

$(objdir)/birdc: $(o)birdc.o
$(objdir)/birdc: LIBS += $(CLIENT_LIBS)

$(objdir)/birdcl: $(o)birdcl.o
