flock-%:
	@python3 -m python.BIRD.Test $*

FLOCK_ALL := $(addprefix flock-, \
	     bgp-secondary \
	     )

flock-all: $(FLOCK_ALL)

.PHONY: flock-all
