src := snmp.c snmp_utils.c subagent.c bgp4_mib.c mib_tree.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(call proto-build,snmp_build)

tests_src := snmp_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
