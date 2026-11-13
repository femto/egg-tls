#!/bin/sh
# Runs test/live.egg against `openssl s_server`, checking the server as
# tls.client does, on a test PKI made here: a P-256 root, a P-384
# intermediate, and leaves for localhost and 127.0.0.1 with P-256, P-384
# and RSA-2048 keys, so the handshake is signed with each of ECDSA P-256,
# ECDSA P-384 and RSA-PSS. Once per cipher suite; then with the P-256
# key share, for a 1 MiB response, and twice where the client must
# refuse (the wrong host, and a CA it does not trust). And through two
# HelloRetryRequests, one for P-384 and one with a cookie (s_server
# -stateless). Needs OpenSSL 1.1.1 or
# later.
#
#     sh test/live.sh                 # clutch from PATH
#     CLUTCH=../egg/bin/clutch sh test/live.sh
set -eu
cd "$(dirname "$0")/.."
CLUTCH=${CLUTCH:-clutch}
PORT=${EGG_TLS_PORT:-44330}
dir=$(mktemp -d)
pid=
cleanup() {
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    rm -rf "$dir"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
# Waits until something listens on $PORT (at most 10 s).
wait_port() {
    i=0
    until nc -z 127.0.0.1 "$PORT" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 100 ]; then
            echo "s_server did not start:" >&2
            cat "$dir/server.log" >&2
            exit 1
        fi
        sleep 0.1
    done
}
# serve CERT [s_server options...]: a TLS 1.3 server with CERT (and its
# key), in the background.
serve() {
    cert=$1
    shift
    (cd "$dir" && exec openssl s_server -quiet -tls1_3 -accept "$PORT" -cert "$cert.pem" \
        -key "$cert.key" "$@" >server.log 2>&1) &
    pid=$!
    wait_port
}
stop() {
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    pid=
}
run() {
    EGG_TLS_PORT=$PORT EGG_TLS_CA="$dir/ca.pem" "$@" ./build/test/live
}

"$CLUTCH" test live >/dev/null    # builds it; without the variables it only returns

printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$dir/ca.ext"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' >"$dir/leaf.ext"
root() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$dir/$1.key" \
        -out "$dir/$1.pem" -subj "/CN=egg-tls $1" -days 2 \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
}
# issue NAME ISSUER EXTENSIONS KEY-OPTIONS...
issue() {
    name=$1 issuer=$2 ext=$3
    shift 3
    openssl req -new "$@" -nodes -keyout "$dir/$name.key" -out "$dir/$name.csr" -subj "/CN=$name" 2>/dev/null
    openssl x509 -req -in "$dir/$name.csr" -CA "$dir/$issuer.pem" -CAkey "$dir/$issuer.key" \
        -CAcreateserial -out "$dir/$name.pem" -days 2 -extfile "$dir/$ext" 2>/dev/null
}
root ca
root other
issue inter ca ca.ext -newkey ec -pkeyopt ec_paramgen_curve:P-384
issue leaf256 ca leaf.ext -newkey ec -pkeyopt ec_paramgen_curve:P-256
issue leaf384 ca leaf.ext -newkey ec -pkeyopt ec_paramgen_curve:P-384
issue leafrsa inter leaf.ext -newkey rsa:2048

for suite in TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384; do
    serve leaf256 -www -ciphersuites "$suite" -groups X25519
    run env EGG_TLS_SUITE=$suite
    stop
done
serve leaf384 -www
printf 'P-384 certificate: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256
stop
serve leafrsa -www -cert_chain inter.pem
printf 'RSA certificate under a P-384 intermediate: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256
stop
serve leaf256 -www -groups P-256
printf 'P-256 key share, host 127.0.0.1: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 EGG_TLS_HOST=127.0.0.1
stop
# HelloRetryRequests: a server that takes only P-384, which the first
# ClientHello offers without a share; and a stateless one, which asks for
# a cookie back.
serve leaf256 -www -groups P-384
printf 'HelloRetryRequest for P-384: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256
stop
serve leaf256 -www -stateless
printf 'HelloRetryRequest with a cookie (-stateless): '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256
stop
serve leaf256 -www
printf 'the wrong host: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 EGG_TLS_HOST=example.com EGG_TLS_EXPECT=HostMismatch
printf 'a CA not trusted: '
EGG_TLS_PORT=$PORT EGG_TLS_CA="$dir/other.pem" EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 \
    EGG_TLS_EXPECT=UnknownIssuer ./build/test/live
stop
# A file of 1 MiB: 64 full records and more, through s_server -HTTP.
head -c 1048576 /dev/urandom >"$dir/big.bin"
serve leaf256 -HTTP
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 \
    EGG_TLS_SHA256="$(openssl dgst -sha256 -r "$dir/big.bin" | cut -d' ' -f1)"
stop
