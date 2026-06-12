# Build PQC examples against in-tree tpm2-tss_pqc shared libraries (never /usr/lib).
# Prerequisite: ./configure && make in repo root.

TOPDIR := ..

# Concrete built library directories (libtool .libs output).
LIBDIR_SYS  := $(abspath $(TOPDIR)/src/tss2-sys/.libs)
LIBDIR_MU   := $(abspath $(TOPDIR)/src/tss2-mu/.libs)
LIBDIR_TCTI := $(abspath $(TOPDIR)/src/tss2-tcti/.libs)

# Real versioned .so files (link these directly, not -ltss2-*).
LIB_TSS2_SYS     := $(firstword $(sort $(wildcard $(LIBDIR_SYS)/libtss2-sys.so.*.*)))
LIB_TSS2_MU      := $(firstword $(sort $(wildcard $(LIBDIR_MU)/libtss2-mu.so.*.*)))
LIB_TSS2_TCTILDR := $(firstword $(sort $(wildcard $(LIBDIR_TCTI)/libtss2-tctildr.so.*.*)))

CC       ?= cc
CFLAGS   += -I$(TOPDIR)/include/tss2 -I$(TOPDIR)/build/include/tss2
LDFLAGS  += -Wl,-rpath,$(LIBDIR_SYS) \
            -Wl,-rpath,$(LIBDIR_MU) \
            -Wl,-rpath,$(LIBDIR_TCTI)
LDLIBS   := $(LIB_TSS2_SYS) $(LIB_TSS2_TCTILDR) $(LIB_TSS2_MU) -ldl

PROGRAMS := pqc-create-primary-demo

.PHONY: all clean check-libs

all: check-libs $(PROGRAMS)

check-libs:
	@test -n "$(LIB_TSS2_SYS)" || \
	    (echo "missing: $(LIBDIR_SYS)/libtss2-sys.so.*.* — run: cd $(TOPDIR) && ./configure && make" >&2; exit 1)
	@test -n "$(LIB_TSS2_MU)" || \
	    (echo "missing: $(LIBDIR_MU)/libtss2-mu.so.*.* — run: cd $(TOPDIR) && ./configure && make" >&2; exit 1)
	@test -n "$(LIB_TSS2_TCTILDR)" || \
	    (echo "missing: $(LIBDIR_TCTI)/libtss2-tctildr.so.*.* — run: cd $(TOPDIR) && ./configure && make" >&2; exit 1)
	@echo "link libs:"
	@echo "  SYS:     $(LIB_TSS2_SYS)"
	@echo "  MU:      $(LIB_TSS2_MU)"
	@echo "  TCTILDR: $(LIB_TSS2_TCTILDR)"
	@echo "rpath:     $(LIBDIR_SYS) $(LIBDIR_MU) $(LIBDIR_TCTI)"

pqc-create-primary-demo: pqc-create-primary-demo.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(PROGRAMS)
