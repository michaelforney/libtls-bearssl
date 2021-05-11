.POSIX:
.PHONY: all install install-static install-shared clean
.SUFFIXES: .c .o .lo

-include config.mk

include shlib_version

VERSION=0.5
PREFIX?=/usr/local
INCDIR?=$(PREFIX)/include
LIBDIR?=$(PREFIX)/lib
MANDIR?=$(PREFIX)/share/man
LDLIBS?=-l bearssl -l pthread
CFLAGS+=-Wall -Wpedantic -D _GNU_SOURCE -I .
CFLAGS_SHARED?=-fPIC
LDFLAGS_SHARED?=-shared -Wl,-soname,libtls.so.$(major) -Wl,--version-script=libtls.ver

OBJ=\
	tls.o\
	tls_bio_cb.o\
	tls_client.o\
	tls_config.o\
	tls_conninfo.o\
	tls_keypair.o\
	tls_ocsp.o\
	tls_peer.o\
	tls_server.o\
	tls_util.o\
	tls_verify.o\
	bearssl.o\
	compat/explicit_bzero.o\
	compat/freezero.o\
	compat/reallocarray.o\
	compat/timingsafe_memcmp.o
LOBJ=$(OBJ:%.o=%.lo)

MAN=\
	man/tls_accept_socket.3\
	man/tls_client.3\
	man/tls_config_ocsp_require_stapling.3\
	man/tls_config_set_protocols.3\
	man/tls_config_set_session_id.3\
	man/tls_config_verify.3\
	man/tls_conn_version.3\
	man/tls_connect.3\
	man/tls_init.3\
	man/tls_load_file.3\
	man/tls_ocsp_process_response.3\
	man/tls_read.3

all: libtls.a libtls.so

$(OBJ): tls.h tls_internal.h compat.h

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.c.lo:
	$(CC) $(CFLAGS) $(CFLAGS_SHARED) -c -o $@ $<

libtls.a: $(OBJ)
	$(AR) cr $@ $(OBJ)

libtls.ver: version-script.sed Symbols.list
	sed -f version-script.sed Symbols.list >$@.tmp && mv $@.tmp $@

libtls.so: $(LOBJ) libtls.ver
	$(CC) $(LDFLAGS) $(LDFLAGS_SHARED) -o $@ $(LOBJ) $(LDLIBS)

libtls.pc: libtls.pc.in
	sed -e "s,@version@,$(VERSION),"\
	    -e "s,@libdir@,$(LIBDIR),"\
	    -e "s,@includedir@,$(INCDIR),"\
	    libtls.pc.in >$@.tmp && mv $@.tmp $@

install-static: libtls.a
	mkdir -p $(DESTDIR)$(LIBDIR)/
	cp libtls.a $(DESTDIR)$(LIBDIR)/

install-shared: libtls.so
	mkdir -p $(DESTDIR)$(LIBDIR)/
	cp libtls.so $(DESTDIR)$(LIBDIR)/libtls.so.$(major).$(minor)
	ln -sf libtls.so.$(major).$(minor) $(DESTDIR)$(LIBDIR)/libtls.so
	ln -sf libtls.so.$(major).$(minor) $(DESTDIR)$(LIBDIR)/libtls.so.$(major)

install: libtls.a libtls.pc install-static install-shared
	mkdir -p $(DESTDIR)$(INCDIR)
	cp tls.h $(DESTDIR)$(INCDIR)/
	mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig/
	cp libtls.pc $(DESTDIR)$(LIBDIR)/pkgconfig/
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	cp $(MAN) $(DESTDIR)$(MANDIR)/man3/

clean:
	rm -f libtls.a libtls.pc libtls.so libtls.ver $(OBJ) $(LOBJ)
