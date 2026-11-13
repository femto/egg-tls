# egg-tls

TLS 1.3 for [Egg](https://github.com/femto/egg), written in Egg: the
hashes, ciphers, key exchange and certificate checks too, with no C
library, the way Zig's `std.crypto.tls` is written in Zig.

**Work in progress**: not usable yet. The plan, bottom up, each part
checked against its RFC's test vectors:

1. hashes: SHA-256, SHA-384/512, HMAC, HKDF (done)
2. AEADs: ChaCha20-Poly1305, AES-128/256-GCM (done)
3. key exchange: X25519 (done); P-256 comes with step 5, which needs the
   curve for ECDSA anyway
4. a TLS 1.3 client: record layer, key schedule, handshake
5. certificates: DER, X.509, ECDSA, RSA, Ed25519, the system's CA bundle,
   host names

It needs an eggc from after [egg #112](https://github.com/femto/egg/pull/112)
(wrapping arithmetic `+%`, `rng.fill` into an array, `@secureZero`), which
the next release will include.

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

## AES-GCM

The same in-place `seal` and `open`, on a value that holds the expanded
key (make one per key, not per message):

```egg
uses io

const aes_gcm = @import("tls/aes_gcm")

fn main(io: Io) !void {
    var key: [16]u8 = @splat(1)
    defer @secureZero(&key)
    var g = aes_gcm.AesGcm.init128(key)    // init256 takes a [32]u8
    defer @secureZero(&g)                  // it holds the expanded key
    const nonce: [12]u8 = @splat(2)        // for show: never twice with one key
    var buf: [21]u8 = @splat(0)
    buf[0] = 'h'
    g.seal(nonce, "header", &buf[0..])
    try g.open(nonce, "header", &buf[0..])
    io.print(buf[0])
}
```

AES is bitsliced, as in BearSSL's `aes_ct64`: four blocks at a time, the
S-box as Boyar and Peralta's circuit of ands and xors, so no table is
indexed by the key or the data. GHASH multiplies through integer products
of words with holes in them (BearSSL's `ghash_ctmul64`), also without
tables. `clutch test` checks the S-box circuit on all 256 bytes, AES
against FIPS 197 and OpenSSL, GHASH against its definition, and AES-GCM
against the GCM paper's test cases and OpenSSL.

## X25519

```egg
uses io, rand

const x25519 = @import("tls/x25519")

fn main(io: Io, rng: Random) !void {
    var mine: [32]u8 = @splat(0)
    defer @secureZero(&mine)                       // gone when main returns
    rng.fill(&mine[0..])                           // 32 random bytes, in place
    const ours = x25519.public_key(mine)           // sent to the peer
    // The peer's public key, received from it; made up here.
    var other: [32]u8 = @splat(0)
    defer @secureZero(&other)
    rng.fill(&other[0..])
    const theirs = x25519.public_key(other)
    var shared = try x25519.shared(mine, theirs)   // error.WeakKey if all zeros
    defer @secureZero(&shared)
    io.print(ours[0], " ", shared[0])
}
```

Field elements are sixteen 16-bit limbs, as in TweetNaCl, and the ladder
swaps by masks, so its time does not depend on the secret. `shared`
refuses an all-zero result, as RFC 8446 requires of a client. `clutch
test` checks it against RFC 7748 (including the iterated test, a thousand
rounds) and against the RFC's algorithm in Ruby's big integers.

## Secrets in memory

What holds a key, or bytes derived from one, for the length of an
operation is zeroed with `@secureZero` (stores the C compiler keeps) when
the operation ends: X25519's scalar, ladder and inversion, HMAC's padded
keys, Poly1305's one-time key, each chunk of AEAD key stream, the tag
mask E(K, J0), GHASH's state (with its key H = E(K, 0)), AES's key
schedule, HKDF's intermediate keys, a hash's state copied to finish it.
Two things are not:

- Values you keep: an `AesGcm`, an `Hmac`, a hash, a key array. Zero them
  when done: `defer @secureZero(&g)`.
- Scratch inside a primitive's single block (ChaCha20's block state, SHA's
  message schedule, AES's bitsliced state, a field multiplication's
  products). The next block overwrites it, and zeroing it every block
  would cost ChaCha20-Poly1305 a further 10-15%.

## License

MIT
