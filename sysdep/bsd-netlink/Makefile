src := netlink.c
obj := $(src-o-files)
$(all-daemon)
$(conf-y-targets): $(s)netlink.Y

$(exedir)/birdc: $(obj)
$(exedir)/birdcl: $(obj)

tests_objs := $(tests_objs) $(src-o-files)
