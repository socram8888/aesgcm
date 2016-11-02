
# Executable
EXEC = aesenc aesdec
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
LIBSOBJ := $(filter-out $(EXEC:%=%.o),$(OBJECTS))

# Disable built-in wildcard rules
.SUFFIXES:

# Keep objects to speed up recompilation
.PRECIOUS: %.o

# Always execute Makefiles for static libraries
.PHONY: $(STATICLIBS)

# Default target: compile all programs
all: $(STATICLIBS) $(EXEC)

%: %.o $(LIBSOBJ)
	$(CC) $(LIBSOBJ) $< -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Static mbed TLS
mbedtls: $(MBEDTLSCONFIG)
	$(MAKE) lib -C $(MBEDTLSDIR) CFLAGS="$(CFLAGS) -DMBEDTLS_CONFIG_FILE='\"$(MBEDTLSCONFIG)\"'"

clean:
	$(RM) $(OBJECTS) $(EXEC)

distclean: clean
	$(MAKE) -C mbedtls clean
