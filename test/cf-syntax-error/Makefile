$(o)%.err: $(s)%.conf $(s)%.err daemon
	@if $(daemon) -l -c $< 2>$@; then echo "Failed config error test $*: passed"; false; fi
	@if diff $(<:.conf=.err) $@; then echo "Config error test $*: OK"; else echo "Failed config error test: $*"; false; fi

$(o)%.ok: $(s)%.conf $(daemon) $(client)
	$(exedir)/bird -l -c $< 2>$@
	$(exedir)/birdcl -l down

ERRS := err-001-empty
OKS := ok-001-minimal

tests_run: $(patsubst %,$(o)%.err,$(ERRS)) $(patsubst %,$(o)%.ok,$(OKS))
dirs += $(s)
