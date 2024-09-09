src := ctl.c flock.c hypervisor.c
obj := $(src-o-files)

flock=$(exedir)/flock-sim

$(flock): $(obj)
$(flock): $(common-lib)
$(flock): LIBS += $(COMMON_LIBS)

$(flock):
	$(E)echo LD $(LDFLAGS) -o $@ $^ $(LIBS)
	$(Q)$(CC) $(LDFLAGS) -o $@ $(patsubst $(common-lib),$(shell cat $(common-lib)),$^) $(LIBS)
