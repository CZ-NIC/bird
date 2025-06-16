src := alloc.c io.c krt.c log.c main.c random.c tools.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)
$(conf-y-targets): $(s)krt.Y

$(client): $(addprefix $(o),alloc.o)

#$(exedir)/birdc: $(o)alloc.o $(o)io.o $(o)krt.o $(o)log.o $(o)random.o $(o)tools.o
#$(exedir)/birdcl: $(o)alloc.o $(o)io.o $(o)krt.o $(o)log.o $(o)random.o $(o)tools.o

src := $(filter-out main.c, $(src))
tests_objs := $(tests_objs) $(src-o-files)
