src := snmp.c snmp_utils.c subagent.c mib_tree.c bgp4_mib.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

tests_src := snmp_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
