PLATFORM ?= $(shell sh -c 'uname -s | tr "[A-Z]" "[a-z]"')
HELPER ?=
BINEXT ?=
SOLIBNAME = libhttp_parser
SOMAJOR = 2
SOMINOR = 8
SOREV   = 1
ifeq (darwin,$(PLATFORM))
SOEXT ?= dylib
SONAME ?= $(SOLIBNAME).$(SOMAJOR).$(SOMINOR).$(SOEXT)
LIBNAME ?= $(SOLIBNAME).$(SOMAJOR).$(SOMINOR).$(SOREV).$(SOEXT)
else ifeq (wine,$(PLATFORM))
CC = winegcc
BINEXT = .exe.so
HELPER = wine
else
SOEXT ?= so
SONAME ?= $(SOLIBNAME).$(SOEXT).$(SOMAJOR).$(SOMINOR)
LIBNAME ?= $(SOLIBNAME).$(SOEXT).$(SOMAJOR).$(SOMINOR).$(SOREV)
endif

CC?=gcc
AR?=ar

CPPFLAGS ?=
LDFLAGS ?=

CPPFLAGS += -I.
CPPFLAGS_DEBUG = $(CPPFLAGS) -DHTTP_PARSER_STRICT=1
CPPFLAGS_DEBUG += $(CPPFLAGS_DEBUG_EXTRA)
CPPFLAGS_FAST = $(CPPFLAGS) -DHTTP_PARSER_STRICT=0
CPPFLAGS_FAST += $(CPPFLAGS_FAST_EXTRA)
CPPFLAGS_BENCH = $(CPPFLAGS_FAST)

CFLAGS += -Wall -Wextra -Werror
CFLAGS_DEBUG = $(CFLAGS) -O0 -g $(CFLAGS_DEBUG_EXTRA)
CFLAGS_FAST = $(CFLAGS) -O3 $(CFLAGS_FAST_EXTRA)
CFLAGS_BENCH = $(CFLAGS_FAST) -Wno-unused-parameter
CFLAGS_LIB = $(CFLAGS_FAST) -fPIC

LDFLAGS_LIB = $(LDFLAGS) -shared

INSTALL ?= install
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include

ifeq (darwin,$(PLATFORM))
LDFLAGS_LIB += -Wl,-install_name,$(LIBDIR)/$(SONAME)
else
# TODO(bnoordhuis) The native SunOS linker expects -h rather than -soname...
LDFLAGS_LIB += -Wl,-soname=$(SONAME)
endif

package: http_parser.o
	$(AR) rcs ./../lib/Linux/libhttp_parser.a http_parser.o

clean:
	rm -f http_parser.o http_parser.a
