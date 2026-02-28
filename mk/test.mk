# Unit tests rules

tests_targets_ok = $(addsuffix .ok,$(tests_targets))

$(tests_targets): %: %.o $(tests_objs) | prepare
	$(E)echo LD $(LDFLAGS) -o $@ $< "..." $(LIBS)
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Hack to avoid problems with tests linking everything
$(tests_targets): LIBS += $(DAEMON_LIBS)

$(tests_targets_ok): %.ok: %
	$(Q)$* 2>/dev/null && touch $*.ok

test: testsclean check
check: tests tests_run
tests: $(tests_targets)
tests_run: $(tests_targets_ok)

testsclean:
	rm -f $(tests_targets_ok)

.PHONY: test_targets_ok test check tests tests_run testsclean

# Static analysis rules

STATIC_CHECKERS_ENABLE := nullability.NullableDereferenced nullability.NullablePassedToNonnull nullability.NullableReturnedFromNonnull optin.portability.UnixAPI valist.CopyToSelf valist.Uninitialized valist.Unterminated
STATIC_CHECKERS_DISABLE := deadcode.DeadStores
STATIC_SCAN_FLAGS := -o $(objdir)/static-scan/ $(addprefix -enable-checker ,$(STATIC_CHECKERS_ENABLE)) $(addprefix -disable-checker ,$(STATIC_CHECKERS_DISABLE))

static-scan:
	$(E)echo Running static code analysis
	$(Q)$(MAKE) clean
	$(Q)scan-build $(STATIC_SCAN_FLAGS) $(MAKE) -$(MAKEFLAGS)

.PHONY: static-scan
