src := io.c krt.c log.c main.c random.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(conf-y-targets): $(s)krt.Y

deps += $(obj-deps)

src := $(filter-out main.c, $(src))
tests_objs := $(tests_objs) $(src-o-files)
