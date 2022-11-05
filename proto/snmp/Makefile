src := snmp.c subagent.c bgp_mib.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,snmp_build)

tests_src := snmp_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
