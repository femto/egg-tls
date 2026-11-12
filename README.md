# egg-tls

TLS 1.3 for [Egg](https://github.com/femto/egg), written in Egg: the
hashes, ciphers, key exchange and certificate checks too, with no C
library, the way Zig's `std.crypto.tls` is written in Zig.

**Work in progress**: not usable yet. The plan, bottom up, each part
checked against its RFC's test vectors:

1. hashes: SHA-256, SHA-384/512, HMAC, HKDF
2. AEADs: ChaCha20-Poly1305, AES-128/256-GCM
3. key exchange: X25519, P-256
4. a TLS 1.3 client: record layer, key schedule, handshake
5. certificates: DER, X.509, ECDSA, RSA, Ed25519, the system's CA bundle,
   host names

It needs an eggc from after [egg #109](https://github.com/femto/egg/pull/109)
(wrapping arithmetic, `+%`), which the next release will include.

## License

MIT
