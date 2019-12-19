
# Executable
BINS = aesgcm
STATICLIBS = mbedcrypto

# Compilation flags
CFLAGS ?= -O2
ALL_CFLAGS = -I $(MBEDCRYPTO_DIR)/include $(CFLAGS) -std=gnu99 -Wall -pedantic
LDFLAGS = -L $(MBEDCRYPTO_DIR)/library -l mbedcrypto

# Commands
INSTALL = /usr/bin/install -D
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

# Directories
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin

# mbed TLS libraries
MBEDCRYPTO_DIR = $(PWD)/mbed-crypto
MBEDCRYPTO_CONFIG = $(PWD)/configs/mbedtls.h
MBEDCRYPTO_CFLAGS = -DMBEDTLS_CONFIG_FILE='\"$(MBEDCRYPTO_CONFIG)\"' $(CFLAGS)

HEADERS := $(wildcard *.h)
OBJECTS := $(patsubst %.c,%.o,$(wildcard *.c))
LIBSOBJ := $(filter-out $(BINS:%=%.o),$(OBJECTS))

# Disable built-in wildcard rules
.SUFFIXES:

# Keep objects to speed up recompilation
.PRECIOUS: %.o

# Always execute Makefiles for static libraries
.PHONY: $(STATICLIBS)

# Default target: compile all programs
all: $(BINS)

%: %.o $(LIBSOBJ) $(STATICLIBS)
	$(CC) $(ALL_CFLAGS) $(LIBSOBJ) $< -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Static mbed TLS
mbedcrypto: $(MBEDCRYPTO_CONFIG)
	$(MAKE) lib -C $(MBEDCRYPTO_DIR) CFLAGS="$(MBEDCRYPTO_CFLAGS)"

# Clean targets
clean: mostlyclean
	$(MAKE) -C $(MBEDCRYPTO_DIR) clean

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
