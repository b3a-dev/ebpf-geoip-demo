.PHONY: clean all
.SUFFIXES:

CILIUM_DIR     =   $(GOPATH)/src/github.com/cilium/cilium/

BPFCC          = clang
BPFCFLAGS      = -O2 -nostdinc -Wall -Wextra -Wshadow -target bpf -emit-llvm -g
BPFCFLAGS     += -I$(CILIUM_DIR)/bpf/include -I$(CILIUM_DIR)/bpf/
BPFLLC         = llc
BPFLLCFLAGS    = -march=bpf -mcpu=probe -mattr=dwarfris

ifneq ($(V),1)
Q ?= @
endif

all: tc-prog.o

%.ll: %.c
	@echo "   BPFC $@"
	$(Q) $(BPFCC) $(BPFCFLAGS) -c  $< -o $@
	$(Q) $(BPFCC) $(BPFCFLAGS) -MM $< -MT $@ -MF $*.d

%.o: %.ll
	@echo "    LLC $@"
	$(Q) $(BPFLLC) $(BPFLLCFLAGS) -filetype=obj  $< -o $@

read-perf: FORCE
	go build -o read-perf

clean:
	rm -f *.o *.ll *.d

FORCE:
