src := alloc.c io.c io-loop.c krt.c log.c main.c random.c domain.c socket.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(conf-y-targets): $(s)krt.Y

src := $(filter-out main.c, $(src))

tests_src := alloc_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
