src := commands.c util.c client.c
obj := $(src-o-files)

$(all-client)
$(conf-y-targets): $(s)cmds.Y

$(exedir)/birdc: $(o)birdc.o
$(exedir)/birdc: LIBS += $(CLIENT_LIBS)

$(exedir)/birdcl: $(o)birdcl.o
