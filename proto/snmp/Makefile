src := snmp.c bgp_mib.c subagent.c
obj := $(src-o-files)
LIBS += `net-snmp-config --agent-libs`
$(all-daemon)
$(cf-local)
$(call proto-build,snmp_build_)

tests_objs := $(tests_objs) $(src-o-files)
