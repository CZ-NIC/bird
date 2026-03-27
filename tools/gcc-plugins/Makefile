# Needs gcc-14-plugin-dev to be installed to build the plugin
GCCPLUGINS_DIR := $(shell $(CXX) -print-file-name=plugin)

LDFLAGS = -shared
CXXFLAGS = -fPIC -fno-rtti -I$(GCCPLUGINS_DIR)/include

%.so: %.cc
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

all: hello.so
