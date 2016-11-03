
# Executable
BINS = aesenc aesdec
STATICLIBS = mbedtls

# mbed TLS libraries
MBEDTLSDIR = $(PWD)/mbedtls
MBEDTLSCONFIG = $(PWD)/configs/mbedtls.h

# Compilation flags
INCLUDES = -I $(MBEDTLSDIR)/include
CFLAGS ?= -Wall -pedantic -O2 $(COPT)
LDFLAGS = -L $(MBEDTLSDIR)/library/ -l mbedcrypto

HEADERS := $(wildcard *.h)
OBJECTS := $(patsubst %.c,%.o,$(wildcard *.c))
LIBSOBJ := $(filter-out $(BINS:%=%.o),$(OBJECTS))

# Commands
INSTALL = /usr/bin/install -D
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

# Directories
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin

# Disable built-in wildcard rules
.SUFFIXES:

# Keep objects to speed up recompilation
.PRECIOUS: %.o

# Always execute Makefiles for static libraries
.PHONY: $(STATICLIBS)

# Default target: compile all programs
all: $(STATICLIBS) $(BINS)

%: %.o $(LIBSOBJ)
	$(CC) $(LIBSOBJ) $< -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Static mbed TLS
mbedtls: $(MBEDTLSCONFIG)
	$(MAKE) lib -C $(MBEDTLSDIR) CFLAGS="$(CFLAGS) -DMBEDTLS_CONFIG_FILE='\"$(MBEDTLSCONFIG)\"'"

# Clean targets
clean: mostlyclean
	$(MAKE) -C $(MBEDTLSDIR) clean

mostlyclean:
	$(RM) $(OBJECTS) $(BINS)

# Install
install: $(BINS:%=install_%)

install_%: %
	$(INSTALL_PROGRAM) $< $(DESTDIR)$(bindir)/$<

# Uninstall
uninstall: $(BINS:%=uninstall_%)

uninstall_%: %
	$(RM) $(DESTDIR)$(bindir)/$<
