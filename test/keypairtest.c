/* $OpenBSD: keypairtest.c,v 1.8 2026/04/15 20:13:07 tb Exp $ */
/*
 * Copyright (c) 2018 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <tls.h>
#include <tls_internal.h>

#include "keypairdata.h"

#define PUBKEY_HASH \
    "SHA256:f03c535d374614e7356c0a4e6fd37fe94297b60ed86212adcba40e8e0b07bc9f"

char *cert_file, *key_file;

static void
load_file(const char *filename, const uint8_t **data, size_t *data_len)
{
	struct stat sb;
	uint8_t *buf;
	size_t len;
	ssize_t n;
	int fd;

	if ((fd = open(filename, O_RDONLY)) == -1)
		err(1, "failed to open '%s'", filename);
	if ((fstat(fd, &sb)) == -1)
		err(1, "failed to stat '%s'", filename);
	if (sb.st_size < 0)
		err(1, "file size invalid for '%s'", filename);
	len = (size_t)sb.st_size;
	if ((buf = malloc(len)) == NULL)
		err(1, "out of memory");
	n = read(fd, buf, len);
	if (n < 0 || (size_t)n != len)
		err(1, "failed to read '%s'", filename);
	close(fd);

	*data = buf;
	*data_len = len;
}

static int
compare_mem(char *label, const uint8_t *data1, size_t data1_len,
    const uint8_t *data2, size_t data2_len)
{
	if (data1_len != data2_len) {
		fprintf(stderr, "FAIL: %s length mismatch (%zu != %zu)\n",
		    label, data1_len, data2_len);
		return -1;
	}
	if (data1 == data2) {
		fprintf(stderr, "FAIL: %s comparing same memory (%p == %p)\n",
		    label, (void *)data1, (void *)data2);
		return -1;
	}
	if (memcmp(data1, data2, data1_len) != 0) {
		fprintf(stderr, "FAIL: %s data mismatch\n", label);
		return -1;
	}
	return 0;
}

static int
compare_key(struct tls_keypair *kp, const br_rsa_private_key *rsa)
{
	if (kp->key_type != BR_KEYTYPE_RSA) {
		fprintf(stderr, "FAIL: key type mismatch\n");
		return -1;
	}
	if (rsa->n_bitlen != kp->key.rsa.n_bitlen) {
		fprintf(stderr, "FAIL: key length mismatch (%"PRIu32" != %"PRIu32")\n",
		    RSA.n_bitlen, kp->key.rsa.n_bitlen);
		return -1;
	}
	if (compare_mem("key P", rsa->p, rsa->plen, kp->key.rsa.p,
	    kp->key.rsa.plen) == -1)
		return -1;
	if (compare_mem("key Q", rsa->q, rsa->qlen, kp->key.rsa.q,
	    kp->key.rsa.qlen) == -1)
		return -1;
	if (compare_mem("key DP", rsa->dp, rsa->dplen, kp->key.rsa.dp,
	    kp->key.rsa.dplen) == -1)
		return -1;
	if (compare_mem("key DQ", rsa->dq, rsa->dqlen, kp->key.rsa.dq,
	    kp->key.rsa.dqlen) == -1)
		return -1;
	if (compare_mem("key IQ", rsa->iq, rsa->iqlen, kp->key.rsa.iq,
	    kp->key.rsa.iqlen) == -1)
		return -1;
	return 0;
}

static int
do_keypair_tests(void)
{
	size_t cert_len, key_len;
	const uint8_t *cert, *key;
	struct tls_keypair *kp;
	struct tls_error err = { 0 };
	int failed = 1;
	size_t i;

	load_file(cert_file, &cert, &cert_len);
	load_file(key_file, &key, &key_len);

	if ((kp = tls_keypair_new()) == NULL) {
		fprintf(stderr, "FAIL: failed to create keypair\n");
		goto done;
	}

	if (tls_keypair_set_cert_file(kp, &err, cert_file) == -1) {
		fprintf(stderr, "FAIL: failed to load cert file: %s\n",
		    err.msg);
		goto done;
	}
	if (tls_keypair_set_key_file(kp, &err, key_file) == -1) {
		fprintf(stderr, "FAIL: failed to load key file: %s\n", err.msg);
		goto done;
	}

	if (kp->chain_len != CHAIN_LEN) {
		fprintf(stderr, "FAIL: incorrect certificate chain length\n");
		goto done;
	}
	for (i = 0; i < kp->chain_len; i++) {
		if (compare_mem("certificate", CHAIN[i].data, CHAIN[i].data_len,
		    kp->chain[i].data, kp->chain[i].data_len) == -1)
			goto done;
	}
	if (compare_key(kp, &RSA) == -1)
		goto done;

	if (tls_keypair_check(kp, &err) != 0) {
		fprintf(stderr, "FAIL: invalid certificate: %s\n",
		    err.msg);
		goto done;
	}

	tls_keypair_clear_key(kp);

	if (kp->key_type != 0 || kp->key_data != NULL || kp->key_data_len != 0) {
		fprintf(stderr, "FAIL: key not cleared (data %p, len %zu)",
		    (void *)kp->key_data, kp->key_data_len);
		goto done;
	}

	if (tls_keypair_set_cert_mem(kp, &err, cert, cert_len) == -1) {
		fprintf(stderr, "FAIL: failed to load cert: %s\n", err.msg);
		goto done;
	}
	if (tls_keypair_set_key_mem(kp, &err, key, key_len) == -1) {
		fprintf(stderr, "FAIL: failed to load key: %s\n", err.msg);
		goto done;
	}

	if (kp->chain_len != sizeof(CHAIN) / sizeof(*CHAIN)) {
		fprintf(stderr, "FAIL: incorrect certificate chain length\n");
		goto done;
	}
	for (i = 0; i < kp->chain_len; i++) {
		if (compare_mem("certificate", CHAIN[i].data, CHAIN[i].data_len,
		    kp->chain[i].data, kp->chain[i].data_len) == -1)
			goto done;
	}
	if (compare_key(kp, &RSA) == -1)
		goto done;

	if (tls_keypair_check(kp, &err) != 0) {
		fprintf(stderr, "FAIL: invalid certificate: %s\n",
		    err.msg);
		goto done;
	}

	tls_keypair_clear_key(kp);

	if (kp->key_type != 0 || kp->key_data != NULL || kp->key_data_len != 0) {
		fprintf(stderr, "FAIL: key not cleared (data %p, len %zu)",
		    (void *)kp->key_data, kp->key_data_len);
		goto done;
	}

	failed = 0;

 done:
	tls_keypair_free(kp);

	return (failed);
}

int
main(int argc, char **argv)
{
	int failure = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s certfile keyfile\n",
		    argv[0]);
		return (1);
	}

	cert_file = argv[1];
	key_file = argv[2];

	failure |= do_keypair_tests();

	return (failure);
}
