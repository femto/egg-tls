# egg-tls

TLS 1.3 for [Egg](https://github.com/femto/egg), written in Egg: the
hashes, ciphers, key exchange and certificate checks too, with no C
library, the way Zig's `std.crypto.tls` is written in Zig.

**Work in progress**: not usable yet. The plan, bottom up, each part
checked against its RFC's test vectors:

1. hashes: SHA-256, SHA-384/512, HMAC, HKDF (done)
2. AEADs: ChaCha20-Poly1305, AES-128/256-GCM (done)
3. key exchange: X25519 (done); P-256 (done, with step 5a)
4. a TLS 1.3 client: record layer, key schedule, handshake (done, but
   without checking the server's certificate)
5. certificates: ECDSA on P-256 and P-384 (done: 5a), RSA (done: 5b); DER,
   X.509, the system's CA bundle, host names (5c); checked in the
   handshake (5d). Ed25519 later

It needs an eggc from after [egg #116](https://github.com/femto/egg/pull/116)
(wrapping arithmetic `+%`, `rng.fill` into an array, `@secureZero`,
`@mulWide`), which the next release will include.

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

## The client

Until step 5 checks certificates, `tls.client` fails with
`error.Unsupported`. `tls.client_unverified` connects **without checking
who answers**: anyone on the path can read and change everything. It is
for tests against a server of your own.

```egg
uses io, alloc, net, rand

const tls = @import("tls")

fn main(io: Io, a: Allocator, net: Net, rng: Random) !void {
    const conn = try net.tcp_connect("127.0.0.1", 4433)
    var c = try tls.client_unverified(a, rng, conn, "localhost")
    defer c.close(a)                       // close_notify, then the socket
    try c.write(a, "GET / HTTP/1.0\r\n\r\n")
    var buf: Buf(u8) = .empty
    defer a.free(buf)
    while (try c.read(a, &buf, 65536) > 0) {   // 0 after close_notify
        io.print(buf)
    }
}
```

It offers ChaCha20-Poly1305, AES-128-GCM and AES-256-GCM (in that order)
and two key shares, X25519 and P-256 (so a server that takes only P-256
needs no HelloRetryRequest), and answers a request for a client certificate
with an empty one. It handles NewSessionTicket (by ignoring it: no
resumption yet) and KeyUpdate, and sends a KeyUpdate of its own every 2^24
records. Not yet: a HelloRetryRequest (`error.HelloRetryUnsupported`),
whether it asks for a group other than those two or
for a cookie to send back; PSK, early data, ALPN, and
sending an alert when it gives up. A connection that ends without a
close_notify is `error.Truncated`.

`tls/client` is the same client with no socket, fed bytes and leaving
what it sends in an outbox. `clutch test` replays RFC 8448's handshake
through it, whole and a byte at a time, and checks every secret and every
record the client sends against the RFC's, byte for byte.
`sh test/live.sh` runs it against `openssl s_server`, once per cipher
suite, and for a 1 MiB response.

## P-256 and P-384

ECDH and ECDSA verification on the NIST curves, as TLS key shares and
certificates use them:

```egg
uses io, rand

const ec = @import("tls/ec")
const ecdsa = @import("tls/ecdsa")

fn main(io: Io, rng: Random) !void {
    const c = ec.p384()                              // or ec.p256()
    var mine: [48]u8 = @splat(0)                     // room for either curve
    defer @secureZero(&mine)
    rng.fill(&mine[0..c.size])                       // c.size bytes: 32 or 48
    // A secret must be below the group's order: draw again if not
    // (about one value in 2^32 on P-256; public_key would say BadScalar).
    while (!usable(c, mine[0..c.size])) {
        rng.fill(&mine[0..c.size])
    }
    var ours: [97]u8 = @splat(0)                     // 1 + 2 * c.size bytes
    try ec.public_key(c, mine[0..c.size], &ours[0..1 + 2 * c.size])
    var shared: [48]u8 = @splat(0)                   // c.size bytes
    defer @secureZero(&shared)
    try ec.shared(c, mine[0..c.size], ours[0..1 + 2 * c.size], &shared[0..c.size])   // with its own key, for show
    // ecdsa.verify_der(c, public_key, digest, der_signature): error.BadSignature
    io.print(ours[0], " ", c.size)
}

fn usable(c: ec.Curve, k: []u8) bool {
    ec.check_scalar(c, k) catch {
        return false
    }
    return true
}
```

Numbers are 64-bit limbs in Montgomery form (`@mulWide` gives each
128-bit product), points projective, added by Renes, Costello and Batina's complete
formulas, so that doubling, the point at infinity and every other case
take one path, and a scalar multiplication doubles and adds for every
bit. Public keys are checked to be on the curve. A scalar multiplication
takes about 0.8 ms on P-256 and 2.4 ms on P-384 (`--release`);
verification makes two. `clutch test` checks ECDH against RFC 5903 and
OpenSSL, and verification against RFC 6979's signatures (SHA-1 to
SHA-512) and OpenSSL's, with signatures, keys and encodings that must be
refused; OpenSSL agreed with every expected answer when the vectors were
made.

## RSA

Verification only, PKCS #1 v1.5 (how most certificates are signed) and
PSS (how TLS 1.3 signs a handshake), with SHA-256, SHA-384 or SHA-512:

```egg
uses io

const rsa = @import("tls/rsa")

fn main(io: Io) !void {
    var modulus: [256]u8 = @splat(0xFF)        // from a certificate, really
    modulus[255] = 0xFB                         // odd, and 2048 bits
    const k = try rsa.public_key(modulus[0..], "\x01\x00\x01")
    const digest: [32]u8 = @splat(0)
    const signature: [256]u8 = @splat(1)
    rsa.verify_pkcs1(k, .sha256, digest[0..], signature[0..]) catch |e| {
        io.print(@errorName(e))                 // BadSignature
    }
    // rsa.verify_pss(k, .sha256, digest, signature, 32): 32 bytes of salt
}
```

Moduli are 2048 to 8192 bits; exponents odd, from 3 to 2^31 - 1. PKCS #1 v1.5
builds the whole encoding a signature must have and compares it, rather
than parsing what the signature gives, which is how Bleichenbacher's 2006
forgeries got past parsers; its DigestInfo must name the hash and carry
its NULL. Signatures are public, so none of this is constant time; a
verification takes well under a millisecond. `clutch test` checks it
against OpenSSL's keys (2048 to 8192 bits, e = 3 too) and signatures,
and against encodings built by hand and signed with the raw private
operation, every expected answer agreed by OpenSSL.

## Secrets in memory

What holds a key, or bytes derived from one, for the length of an
operation is zeroed with `@secureZero` (stores the C compiler keeps) when
the operation ends: X25519's scalar, ladder and inversion, HMAC's padded
keys, Poly1305's one-time key, each chunk of AEAD key stream, the tag
mask E(K, J0), GHASH's state (with its key H = E(K, 0)), AES's key
schedule, HKDF's intermediate keys, a hash's state copied to finish it,
and the client's X25519 and P-256 secrets (once used), its handshake secrets (once
the handshake is over), and the rest of its keys and the application data
it holds when it is closed. Two things are not:

- Values you keep: an `AesGcm`, an `Hmac`, a hash, a key array. Zero them
  when done: `defer @secureZero(&g)`.
- Scratch inside a primitive's single block (ChaCha20's block state, SHA's
  message schedule, AES's bitsliced state, a field multiplication's
  products). The next block overwrites it, and zeroing it every block
  would cost ChaCha20-Poly1305 a further 10-15%.

## License

MIT
