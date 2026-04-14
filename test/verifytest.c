/*	$OpenBSD: verifytest.c,v 1.8 2023/05/28 09:02:01 beck Exp $	*/
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <bearssl.h>
#include <x509cert.h>

#include <tls.h>

extern int tls_check_name(struct tls *ctx, br_x509_certificate *cert,
    const char *name, int *match);

struct alt_name {
	unsigned char name[128];
	int name_len;
	int name_type;
};

struct verify_test {
	const char common_name[128];
	int common_name_len;
	struct alt_name alt_name1;
	struct alt_name alt_name2;
	struct alt_name alt_name3;
	const char name[128];
	int want_return;
	int want_match;
	int name_type;
};

struct verify_test verify_tests[] = {
	{
		/* CN without SANs - matching. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
#if 0
	{
		/* Zero length name - non-matching. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.name = "",
		.want_return = 0,
		.want_match = 0,
	},
#endif
	{
		/* CN wildcard without SANs - matching. */
		.common_name = "*.openbsd.org",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* CN without SANs - non-matching. */
		.common_name = "www.openbsdfoundation.org",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN wildcard without SANs - invalid CN wildcard. */
		.common_name = "w*.openbsd.org",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN wildcard without SANs - invalid CN wildcard. */
		.common_name = "www.*.org",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN wildcard without SANs - invalid CN wildcard. */
		.common_name = "www.openbsd.*",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN wildcard without SANs - invalid CN wildcard. */
		.common_name = "*",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN wildcard without SANs - invalid CN wildcard. */
		.common_name = "*.org",
		.common_name_len = -1,
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
#if 0
	/* XXX: Should BearSSL accept wildcards under TLD? */
	{
		/* CN wildcard without SANs - invalid CN wildcard. */
		.common_name = "*.org",
		.common_name_len = -1,
		.name = "openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
#endif
	{
		/* CN IPv4 without SANs - matching. */
		.common_name = "1.2.3.4",
		.common_name_len = -1,
		.name = "1.2.3.4",
		.want_return = 0,
		.want_match = 1,
	},
#if 0
	/* XXX: Should BearSSL accept IP address wildcards? */
	{
		/* CN IPv4 wildcard without SANS - invalid IP wildcard. */
		.common_name = "*.2.3.4",
		.common_name_len = -1,
		.name = "1.2.3.4",
		.want_return = 0,
		.want_match = 0,
	},
#endif
	{
		/* CN IPv6 without SANs - matching. */
		.common_name = "cafe::beef",
		.common_name_len = -1,
		.name = "cafe::beef",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* CN without SANs - error due to embedded NUL in CN. */
		.common_name = {
			0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65, 0x6e,
			0x62, 0x73, 0x64, 0x2e, 0x6f, 0x72, 0x67, 0x00,
			0x6e, 0x61, 0x73, 0x74, 0x79, 0x2e, 0x6f, 0x72,
			0x67,
		},
		.common_name_len = 25,
		.name = "www.openbsd.org",
		.want_return = -1,
		.want_match = 0,
	},
#if 0
	/* XXX: Should BearSSL accept zero-length wildcards */
	{
		/* CN wildcard without SANs - invalid non-matching name. */
		.common_name = "*.openbsd.org",
		.common_name_len = -1,
		.name = ".openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
#endif
	{
		/* CN with SANs - matching on first SAN. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "ftp.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* SANs only - matching on first SAN. */
		.common_name_len = 0,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "ftp.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* SANs only - matching on second SAN. */
		.common_name_len = 0,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "ftp.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "ftp.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* SANs only - non-matching. */
		.common_name_len = 0,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "ftp.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "mail.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN with SANs - matching on second SAN. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "ftp.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "ftp.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* CN with SANs - matching on wildcard second SAN. */
		.common_name = "www.openbsdfoundation.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsdfoundation.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "*.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 1,
	},
	{
		/* CN with SANs - non-matching invalid wildcard. */
		.common_name = "www.openbsdfoundation.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsdfoundation.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "*.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
#if 0
	/* BearSSL doesn't check if the domain name is an IP address */
	{
		/* CN with SANs - non-matching IPv4 due to GEN_DNS SAN. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = "1.2.3.4",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "1.2.3.4",
		.want_return = 0,
		.want_match = 0,
	},
#endif
#if 0
	/* BearSSL doesn't support iPAddress SANs */
	{
		/* CN with SANs - matching IPv4 on GEN_IPADD SAN. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = {0x01, 0x02, 0x03, 0x04},
			.name_len = 4,
			.name_type = X509CERT_SAN_IPADDRESS,
		},
		.name = "1.2.3.4",
		.want_return = 0,
		.want_match = 1,
	},
#endif
#if 0
	/* BearSSL doesn't support iPAddress SANs */
	{
		/* CN with SANs - matching IPv6 on GEN_IPADD SAN. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = {
				0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef,
			},
			.name_len = 16,
			.name_type = X509CERT_SAN_IPADDRESS,
		},
		.name = "cafe::beef",
		.want_return = 0,
		.want_match = 1,
	},
#endif
	{
		/* CN with SANs - error due to embedded NUL in GEN_DNS. */
		.common_name = "www.openbsd.org.nasty.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "www.openbsd.org.nasty.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.alt_name2 = {
			.name = {
				0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65, 0x6e,
				0x62, 0x73, 0x64, 0x2e, 0x6f, 0x72, 0x67, 0x00,
				0x6e, 0x61, 0x73, 0x74, 0x79, 0x2e, 0x6f, 0x72,
				0x67,
			},
			.name_len = 25,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = -1,
		.want_match = 0,
	},
	{
		/* CN with SAN - non-matching due to non-matching SAN. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = "ftp.openbsd.org",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = 0,
		.want_match = 0,
	},
	{
		/* CN with SAN - error due to illegal dNSName. */
		.common_name = "www.openbsd.org",
		.common_name_len = -1,
		.alt_name1 = {
			.name = " ",
			.name_len = -1,
			.name_type = X509CERT_SAN_DNSNAME,
		},
		.name = "www.openbsd.org",
		.want_return = -1,
		.want_match = 0,
	},
};

#define N_VERIFY_TESTS \
    (sizeof(verify_tests) / sizeof(*verify_tests))

static void
alt_names_add(struct x509cert_req *req, size_t alts_max, struct alt_name *alt)
{
	struct x509cert_item *alt_name;

	if (req->alts_len == alts_max)
		errx(1, "too many alt names");
	alt_name = &req->alts[req->alts_len++];

	alt_name->tag = alt->name_type;
	alt_name->enc = NULL;
	switch (alt_name->tag) {
	case X509CERT_SAN_DNSNAME:
		alt_name->len = alt->name_len > 0 ? alt->name_len : strlen((char *)alt->name);
		alt_name->val = alt->name;
		break;
	case X509CERT_SAN_IPADDRESS:
		if (alt->name_len < 0)
			errx(1, "alt name X509CERT_SAN_IPADDRESS must have non-negative length");
		alt_name->len = alt->name_len;
		alt_name->val = alt->name;
		break;
	default:
		errx(1, "unknown alt name type (%d)", alt_name->tag);
	}
}

static void
cert_add_alt_names(struct x509cert_req *req, size_t alts_max, struct verify_test *vt)
{
	if (vt->alt_name1.name_type != 0)
		alt_names_add(req, alts_max, &vt->alt_name1);
	if (vt->alt_name2.name_type != 0)
		alt_names_add(req, alts_max, &vt->alt_name2);
	if (vt->alt_name3.name_type != 0)
		alt_names_add(req, alts_max, &vt->alt_name3);
}

/* arbitrary EC key pair for self-signing generated certificates */
static const unsigned char skey_x[] = {
	0x2C, 0xF5, 0xA7, 0x1D, 0x90, 0x48, 0xFE, 0x2A, 0x28, 0x87, 0xDF, 0xF0,
	0x43, 0x51, 0x94, 0xD0, 0x9E, 0xBE, 0xC1, 0x37, 0x3B, 0xDA, 0xE2, 0xA6,
	0xDC, 0xD9, 0x0F, 0x54, 0x2B, 0xFA, 0x5A, 0x06
};

static const br_ec_private_key skey_ec = {
	.curve = BR_EC_secp256r1,
	.x = (unsigned char *)skey_x,
	.xlen = sizeof(skey_x),
};

static const struct x509cert_skey skey = {
	.type = BR_KEYTYPE_EC,
	.u.ec = &skey_ec,
};

static const unsigned char pkey_q[] = {
	0x04, 0xEC, 0xE2, 0x25, 0xBC, 0x39, 0xF4, 0x3A, 0x8B, 0xDC, 0x46, 0x99,
	0xAE, 0x8D, 0x53, 0x02, 0xEF, 0x86, 0xD6, 0x3B, 0xB2, 0x47, 0x86, 0x93,
	0xF9, 0xB6, 0x7C, 0x7F, 0x76, 0xC8, 0x8D, 0x5A, 0xE8, 0xCF, 0x0D, 0xA2,
	0x41, 0xF6, 0x1B, 0x5F, 0xA9, 0x62, 0x25, 0x90, 0x53, 0xED, 0xC3, 0x35,
	0xD1, 0x47, 0x2D, 0xFF, 0x23, 0x07, 0x4B, 0x68, 0x73, 0xCA, 0xFF, 0xDE,
	0xC0, 0x70, 0x45, 0xDA, 0x44
};

static const br_x509_pkey pkey = {
	.key_type = BR_KEYTYPE_EC,
	.key.ec = {
		.curve = BR_EC_secp256r1,
		.q = (unsigned char *)pkey_q,
		.qlen = sizeof(pkey_q),
	},
};

static int
do_verify_test(int test_no, struct verify_test *vt)
{
	struct x509cert_rdn rdn = {
		.oid = x509cert_oid_CN,
		.val.tag = X509CERT_ASN1_UTF8STRING,
	};
	struct x509cert_dn dn = {
		.rdn = NULL,
		.rdn_len = 0,
	};
	struct x509cert_item alts[3];
	struct x509cert_req req = {
		.subject = {
			.enc = x509cert_dn_encoder,
			.val = &dn,
		},
		.pkey = pkey,
		.alts = alts,
	};
	struct x509cert_cert x509 = {
		.req = &req,
		.key_type = pkey.key_type,
		.hash_id = br_sha256_ID,
		.issuer = {
			.enc = x509cert_dn_encoder,
			.val = &dn,
		},
		.notbefore = 0,
		.notafter = 253402300799, /* 99991231235959Z */
	};
	struct x509cert_item x509_item = {
		.enc = x509cert_cert_encoder,
		.val = &x509,
	};
	size_t cert_max;
	br_x509_certificate cert;
	struct tls *tls;
	int failed = 1;
	int result, match;

	/* Build certificate structure. */
	if (vt->common_name_len != 0) {
		rdn.val.val = vt->common_name;
		rdn.val.len = vt->common_name_len > 0 ? vt->common_name_len :
		    strlen(vt->common_name);
		dn.rdn = &rdn;
		dn.rdn_len = 1;
	}

	if ((tls = tls_client()) == NULL)
		errx(1, "failed to malloc tls_client");

	cert_add_alt_names(&req, sizeof(alts) / sizeof(alts[0]), vt);

	/* self-sign certificate */
	cert_max = x509cert_sign(&x509_item, &skey, &br_sha256_vtable, NULL);
	if (cert_max == 0 || (cert.data = malloc(cert_max)) == NULL)
		errx(1, "failed to sign certificate");
	cert.data_len = x509cert_sign(&x509_item, &skey, &br_sha256_vtable, cert.data);
	if (cert.data_len == 0)
		errx(1, "failed to sign certificate");

	match = 1;

	result = tls_check_name(tls, &cert, vt->name, &match);
	if (result == 0) {
		if (match != vt->want_match) {
			fprintf(stderr, "FAIL: test %i failed to match name '%s'\n",
			    test_no, vt->name);
			goto done;
		}
		/* ignore want_return if it matched correctly */
	} else if (result != vt->want_return) {
		if (tls_check_name(tls, &cert, vt->name, &match) != vt->want_return) {
			fprintf(stderr, "FAIL: test %i failed for check name '%s': "
			    "%s\n", test_no, vt->name, tls_error(tls));
			goto done;
		}
	}

	failed = 0;

 done:
	tls_free(tls);

	return (failed);
}

int
main(int argc, char **argv)
{
	int failed = 0;
	size_t i;

	tls_init();

	for (i = 0; i < N_VERIFY_TESTS; i++)
		failed += do_verify_test(i, &verify_tests[i]);

	return (failed);
}
