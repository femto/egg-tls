# egg-tls

TLS 1.3 for [Egg](https://github.com/femto/egg), written in Egg: the
hashes, ciphers, key exchange and certificate checks too, with no C
library, the way Zig's `std.crypto.tls` is written in Zig.

**Work in progress**: not usable yet. The plan, bottom up, each part
checked against its RFC's test vectors:

1. hashes: SHA-256, SHA-384/512, HMAC, HKDF (done)
2. AEADs: ChaCha20-Poly1305 (done), AES-128/256-GCM
3. key exchange: X25519, P-256
4. a TLS 1.3 client: record layer, key schedule, handshake
5. certificates: DER, X.509, ECDSA, RSA, Ed25519, the system's CA bundle,
   host names

It needs an eggc from after [egg #109](https://github.com/femto/egg/pull/109)
(wrapping arithmetic, `+%`), which the next release will include.

## The hashes

Each is a module of the package, usable on its own:

```egg
uses io

const sha256 = @import("tls/sha256")
const hmac = @import("tls/hmac")
const hkdf = @import("tls/hkdf")

fn main(io: Io) !void {
    const d = sha256.sum("abc")              // [32]u8; sha512.sum384, sum512 too
    var h = sha256.Sha256.init()             // or step by step; a copy keeps
    h.update("ab")                           // the hash so far
    h.update("c")
    var m = hmac.Hmac(sha256.Sha256).init("key")
    m.update("message")
    var tag: [32]u8 = @splat(0)
    m.final(&tag[0..])
    var prk: [32]u8 = @splat(0)
    hkdf.Hkdf(sha256.Sha256).extract("salt", "input key", &prk[0..])
    var okm: [42]u8 = @splat(0)
    try hkdf.Hkdf(sha256.Sha256).expand(prk[0..], "info", &okm[0..])
    io.print(d[0], " ", h.final()[0], " ", tag[0], " ", okm[0])
}
```

`clutch test` checks them against FIPS 180-4 (RFC 6234), RFC 4231 and
RFC 5869.

## ChaCha20-Poly1305

In place, in one pass, on one buffer. Before `seal` it holds the plaintext
and then 16 spare bytes; after it, the ciphertext and then the tag, which
is how a TLS record carries them. `open` turns that back into the
plaintext (the last 16 bytes are left as they were).

```egg
uses io

const cp = @import("tls/chacha20poly1305")

fn main(io: Io) !void {
    const key: [32]u8 = @splat(1)
    const nonce: [12]u8 = @splat(2)        // never twice with one key
    var buf: [21]u8 = @splat(0)
    buf[0] = 'h'                            // 5 bytes of plaintext, 16 for the tag
    cp.seal(key, nonce, "header", &buf[0..])
    try cp.open(key, nonce, "header", &buf[0..])   // error.AuthFailed, and
    io.print(buf[0])                               // all zeros, if changed
}
```

Its time depends on lengths only, not on the key, the data or where a
forged tag differs. `clutch test` checks it against RFC 8439, OpenSSL,
and Poly1305 computed from its definition, including the edges of its
final reduction.

## License

MIT
