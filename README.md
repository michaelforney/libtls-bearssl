# libtls-bearssl

[![builds.sr.ht status](https://builds.sr.ht/~mcf/libtls-bearssl.svg)](https://builds.sr.ht/~mcf/libtls-bearssl)

libtls-bearssl is an implementation of [libtls] on top of [BearSSL].

BearSSL is an excellent TLS library: it is small, secure by default,
flexible, consistent, performs no memory allocation, and the code
is as clean and well documented as any I've ever seen.

However, due to some of its constraints, it is not the easiest TLS
library to use. Things like loading trust anchors, server-side SNI,
and I/O with non-blocking sockets actually involve quite a bit of
work.

libtls shares some of the same goals as BearSSL: it is also consistent,
secure by default, and well documented. However, it is also a
higher-level API that is designed to be easy to use for many common
situations.

This project aims to get the best of both worlds by implementing
the libtls API on top of BearSSL.

## Status

libtls-bearssl implements nearly all features of the libtls API
(version 3.3.3).  However, there are some that are missing, since
they are not supported by BearSSL.

- OCSP stapling. Attempts to configure this will fail.
- Certificate revocation list (CRL). Attempts to configure this
  will fail.
- Inspecting peer certificate issuer name. `tls_peer_cert_issuer`
  always returns `NULL`.
- Inspecting peer certificate notBefore and notAfter times.
  `tls_peer_cert_notbefore` and `tls_peer_cert_notafter` always
  return `-1`.
- Encrypted key files. If `tls_load_file` is passed a password
  string, it will return `NULL`.
- Session caching. BearSSL does implement this (though not session
  tickets, RFC 5077), so this may be added in the future.
- Keys and certificates using CRLF as the line ending are not
  supported. They must first be converted to use unix-style line
  endings (LF).

## Mailing list

Feel free to use the mailing list at
https://lists.sr.ht/~mcf/libtls-bearssl for patches, questions, or
general discussion.

## Issue tracker

Please report any issues to https://todo.sr.ht/~mcf/libtls-bearssl.

[libtls]: http://man.openbsd.org/tls_init
[BearSSL]: https://bearssl.org/
