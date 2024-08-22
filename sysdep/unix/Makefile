src := alloc.c domain.c file.c io-loop.c log.c socket.c random.c time.c
obj := $(src-o-files)
$(all-lib)

src := io.c io-cli.c krt.c main.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(conf-y-targets): $(s)krt.Y

src := $(filter-out main.c, $(src))

tests_src := alloc_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
