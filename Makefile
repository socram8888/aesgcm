
# Executable
EXEC = aesenc aesdec
STATICLIBS = mbedtls

# mbed TLS libraries
MBEDTLSINCLUDE = $(PWD)/mbedtls/include
MBEDTLSCONFIG = $(PWD)/configs/mbedtls.h

# Compilation flags
INCLUDES = -I $(MBEDTLSINCLUDE)
CFLAGS = -Wall -pedantic -O3 $(INCLUDES) $(COPT)
LDFLAGS = -L mbedtls/library/ -l mbedcrypto

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
	$(CC) $(CFLAGS) -c $< -o $@

# Static mbed TLS
mbedtls: $(MBEDTLSCONFIG)
	$(MAKE) lib -C mbedtls CFLAGS="-DMBEDTLS_CONFIG_FILE='\"$(MBEDTLSCONFIG)\"'"

clean:
	$(RM) $(OBJECTS) $(EXEC)

distclean: clean
	$(MAKE) -C mbedtls clean
