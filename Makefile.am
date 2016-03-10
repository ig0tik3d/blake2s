
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  hash/sha256d/sha2.c hash/scrypt/scrypt.c \
		  hash/blake2/sse/blake2s.c hash/blake2/blake2.c
if ARCH_x86
minerd_SOURCES += hash/sha256d/sha2-x86.S hash/scrypt/scrypt-x86.S
endif
if ARCH_x86_64
minerd_SOURCES += hash/sha256d/sha2-x64.S hash/scrypt/scrypt-x64.S
endif
if ARCH_ARM
minerd_SOURCES += hash/sha256d/sha2-arm.S hash/scrypt/scrypt-arm.S
endif
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ 
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

