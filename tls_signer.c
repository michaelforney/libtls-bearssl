/* $OpenBSD: tls_signer.c,v 1.13 2024/06/11 16:35:24 op Exp $ */
/*
 * Copyright (c) 2021 Eric Faurot <eric@openbsd.org>
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

#include <stdlib.h>
#include <string.h>

#include "tls.h"
#include "tls_internal.h"

struct tls_signer_key {
	char *hash;
	struct tls_signer_key *next;
};

struct tls_signer {
	struct tls_error error;
	struct tls_signer_key *keys;
};

struct tls_signer *
tls_signer_new(void)
{
	struct tls_signer *signer;

	if ((signer = calloc(1, sizeof(*signer))) == NULL)
		return (NULL);

	return (signer);
}

void
tls_signer_free(struct tls_signer *signer)
{
	struct tls_signer_key *skey;

	if (signer == NULL)
		return;

	tls_error_clear(&signer->error);

	while (signer->keys) {
		skey = signer->keys;
		signer->keys = skey->next;
		free(skey->hash);
		free(skey);
	}

	free(signer);
}

const char *
tls_signer_error(struct tls_signer *signer)
{
	return (signer->error.msg);
}

int
tls_signer_add_keypair_mem(struct tls_signer *signer, const uint8_t *cert,
    size_t cert_len, const uint8_t *key, size_t key_len)
{
	tls_error_setx(&signer->error, TLS_ERROR_UNKNOWN, "not implemented");

	return (-1);
}

int
tls_signer_add_keypair_file(struct tls_signer *signer, const char *cert_file,
    const char *key_file)
{
	tls_error_setx(&signer->error, TLS_ERROR_UNKNOWN, "not implemented");

	return (-1);
}

int
tls_signer_sign(struct tls_signer *signer, const char *pubkey_hash,
    const uint8_t *input, size_t input_len, int padding_type,
    uint8_t **out_signature, size_t *out_signature_len)
{
	struct tls_signer_key *skey;

	*out_signature = NULL;
	*out_signature_len = 0;

	for (skey = signer->keys; skey; skey = skey->next)
		if (!strcmp(pubkey_hash, skey->hash))
			break;

	tls_error_setx(&signer->error, TLS_ERROR_UNKNOWN, "not implemented");

	return (-1);
}
