src := snmp.c subagent.c
obj := $(src-o-files)
LIBS += `net-snmp-config --agent-libs`
$(all-daemon)
$(cf-local)
$(call proto-build,snmp_build)

tests_objs := $(tests_objs) $(src-o-files)
