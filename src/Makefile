CC := cc
LLC ?= llc
CLANG ?= clang


OPT = -O2
WARN = -Wall -Wno-unused-value -Wno-pointer-sign -Werror


BPF_CFLAGS = -I/lib/modules/`uname -r`/source/tools/perf -I/lib/modules/`uname -r`/source/tools/testing/selftests/bpf -I./
BPF_DEFINE = -D__BPF_TRACING__


CFLAGS = -I/lib/modules/`uname -r`/source/tools/perf -I/lib/modules/`uname -r`/source/tools/lib/bpf -I/lib/modules/`uname -r`/source/tools/include
LDFLAGS = -L/lib/modules/`uname -r`/source/tools/lib/bpf
LIBS = -l:libbpf.a -lelf


BPF_SOCKOPS=bpf-sockops
BPF_REDIR=bpf-redir


Q = @
E = @echo


INSTALL =  cp -pf
INSTALL_BIN ?= /usr/local/bin


%.o: %.c
	$(E) "CC        $@"
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) $(WARN) $(LIBS) $(OPT) $(DEBUG) $(DEFINE) -g -c -o $@ $<


all: $(BPF_SOCKOPS) $(BPF_REDIR)


$(BPF_SOCKOPS): bpf_sockops.c
	$(E) "CLANG     $@"
	$(Q)$(CLANG) $^ -target bpf $(BPF_DEFINE) $(BPF_CFLAGS) $(WARN) -O2 -emit-llvm -c -g -o -| $(LLC) -march=bpf -filetype=obj -o $@


$(BPF_REDIR): bpf_redir.c
	$(E) "CLANG     $@"
	$(Q)$(CLANG) $^ -target bpf $(BPF_DEFINE) $(BPF_CFLAGS) $(WARN) -O2 -emit-llvm -c -g -o -| $(LLC) -march=bpf -filetype=obj -o $@


.PHONY: clean

clean:
	rm -f $(BPF_SOCKOPS) $(BPF_REDIR)

.PHONY: install
	
install: all
	$(Q)mkdir -p $(INSTALL_BIN)
	$(INSTALL) $(BPF_SOCKOPS) $(BPF_REDIR) $(INSTALL_BIN)


.PHONY: uninstall

uninstall:
	rm -f $(INSTALL_BIN)/{$(BPF_REDIR),$(BPF_SOCKOPS)}
