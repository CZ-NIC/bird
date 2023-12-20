src := krt-sock.c
obj := $(src-o-files)
$(all-daemon)
$(conf-y-targets): $(s)krt-sock.Y

$(exedir)/birdc: $(obj)
$(exedir)/birdcl: $(obj)

tests_objs := $(tests_objs) $(src-o-files)
