.POSIX:
.PHONY: all clean

-include config.mk

PREFIX?=/usr/local
INCDIR?=$(PREFIX)/include
LIBDIR?=$(PREFIX)/lib
MANDIR?=$(PREFIX)/share/man
CFLAGS+=-Wall -Wpedantic -D _DEFAULT_SOURCE -I .

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
	compat/freezero.o\
	compat/reallocarray.o\
	compat/timingsafe_memcmp.o

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

all: libtls.a

$(OBJ): tls.h tls_internal.h compat.h

libtls.a: $(OBJ)
	$(AR) cr $@ $(OBJ)

install: libtls.a tls.h $(MAN)
	mkdir -p $(DESTDIR)$(INCDIR)
	cp tls.h $(DESTDIR)$(INCDIR)/
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp libtls.a $(DESTDIR)$(LIBDIR)/
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	cp $(MAN) $(DESTDIR)$(MANDIR)/man3/

clean:
	rm -f libtls.a $(OBJ)
