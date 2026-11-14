#!/bin/sh
# Runs test/live.egg against `openssl s_server`, checking the server as
# tls.client does, on a test PKI made here: a P-256 root, a P-384
# intermediate, and leaves for localhost and 127.0.0.1 with P-256, P-384
# and RSA-2048 keys, so the handshake is signed with each of ECDSA P-256,
# ECDSA P-384 and RSA-PSS. Once per cipher suite; then with the P-256
# key share, for a 1 MiB response, and twice where the client must
# refuse (the wrong host, and a CA it does not trust), where the server
# must log the client's alert (bad_certificate, unknown_ca). And through two
# HelloRetryRequests, one for P-384 and one with a cookie (s_server
# -stateless). tls/https (test/live_https.egg): a body that runs to
# the connection's end from s_server -WWW, then redirects, headers and
# refusals from test/https_server.py (python3). ALPN: a server with -alpn h2,http/1.1 must choose the
# first of its own the client offers, and refuse (no_application_protocol) when
# there is none; a server without -alpn chooses none. Needs OpenSSL
# 1.1.1 or later.
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
    (cd "$dir" && exec openssl s_server -tls1_3 -accept "$PORT" -cert "$cert.pem" \
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
"$CLUTCH" test live_https >/dev/null

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
# ALPN. s_server -alpn takes the first of its own list the client offers,
# so h2 here although the client lists http/1.1 before it.
serve leaf256 -www -alpn h2,http/1.1
printf 'ALPN, the server choosing: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 EGG_TLS_ALPN=spdy/1,http/1.1,h2 EGG_TLS_WANT_ALPN=h2
printf 'ALPN, nothing offered: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256
printf 'ALPN, none in common: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 EGG_TLS_ALPN=spdy/1 EGG_TLS_EXPECT=AlertReceived
grep -q 'no application protocol' "$dir/server.log" || { echo "FAIL the server did not refuse for ALPN:" >&2; cat "$dir/server.log" >&2; exit 1; }
stop
serve leaf256 -www
printf 'ALPN offered to a server without it: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 EGG_TLS_ALPN=h2
# server_alert N: the server logged receiving alert N from the client.
# It may log a little after the client exits: up to 2 s.
server_alert() {
    i=0
    until grep -q "SSL alert number $1\$" "$dir/server.log"; do
        i=$((i + 1))
        if [ "$i" -gt 20 ]; then
            echo "FAIL the server did not get alert $1:" >&2
            cat "$dir/server.log" >&2
            exit 1
        fi
        sleep 0.1
    done
    echo "  the server got alert $1"
}
printf 'the wrong host: '
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 EGG_TLS_HOST=example.com EGG_TLS_EXPECT=HostMismatch
server_alert 42
printf 'a CA not trusted: '
EGG_TLS_PORT=$PORT EGG_TLS_CA="$dir/other.pem" EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 \
    EGG_TLS_EXPECT=UnknownIssuer ./build/test/live
server_alert 48
stop
# A file of 1 MiB: 64 full records and more, through s_server -HTTP.
head -c 1048576 /dev/urandom >"$dir/big.bin"
serve leaf256 -HTTP
run env EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 \
    EGG_TLS_SHA256="$(openssl dgst -sha256 -r "$dir/big.bin" | cut -d' ' -f1)"
stop
# tls/https. A body without a length, which ends at the connection's end,
# from s_server -WWW: it must end with close_notify.
big_sha=$(openssl dgst -sha256 -r "$dir/big.bin" | cut -d' ' -f1)
fetch() {
    printf '%s: ' "$1"
    shift
    env EGG_TLS_CA="$dir/ca.pem" "$@" ./build/test/live_https
}
serve leaf256 -WWW
fetch 'https: a body to the end' EGG_TLS_URL="https://localhost:$PORT/big.bin" EGG_TLS_SHA256="$big_sha"
stop
# Redirects, headers and refusals, from a server of Python's.
mkdir "$dir/files" && cp "$dir/big.bin" "$dir/files/"
python3 test/https_server.py "$PORT" "$dir/leaf256.pem" "$dir/leaf256.key" "$dir/files" >"$dir/server.log" 2>&1 &
pid=$!
wait_port
u="https://localhost:$PORT"
fetch 'https: a file' EGG_TLS_URL="$u/file/big.bin" EGG_TLS_SHA256="$big_sha"
fetch 'https: HEAD' EGG_TLS_METHOD=HEAD EGG_TLS_URL="$u/file/big.bin" EGG_TLS_WANT_STATUS=200 EGG_TLS_SHA256="$(printf '' | openssl dgst -sha256 -r | cut -d' ' -f1)"
fetch 'https: the request' EGG_TLS_URL="$u/headers?q=1" EGG_TLS_HEADER="X-Egg: 1" \
    EGG_TLS_HAS="$(printf 'GET /headers?q=1\r\nHost: localhost:%s\r\nX-Egg: 1\r\nConnection: close' "$PORT")"
fetch 'https: a 302 not followed' EGG_TLS_URL="$u/redirect" EGG_TLS_WANT_STATUS=302
fetch 'https: a 302 followed' EGG_TLS_URL="$u/redirect" EGG_TLS_REDIRECTS=1 EGG_TLS_SHA256="$big_sha"
fetch 'https: a 301 to an absolute URL, same origin' EGG_TLS_URL="$u/absolute" EGG_TLS_REDIRECTS=1 \
    EGG_TLS_HEADER="X-Egg: 1" EGG_TLS_HAS="X-Egg: 1"
fetch 'https: to another host, without the headers' EGG_TLS_URL="$u/other-host" EGG_TLS_REDIRECTS=1 \
    EGG_TLS_HEADER="X-Egg: 1" EGG_TLS_WANT_STATUS=200 EGG_TLS_HAS="Host: 127.0.0.1:$PORT" EGG_TLS_LACKS="X-Egg"
fetch 'https: a 303 after a POST, as a GET' EGG_TLS_METHOD=POST EGG_TLS_BODY=hello EGG_TLS_URL="$u/see-other" \
    EGG_TLS_REDIRECTS=1 EGG_TLS_HAS="GET /headers" EGG_TLS_LACKS="Content-Length"
fetch 'https: not down to http://' EGG_TLS_URL="$u/to-http" EGG_TLS_REDIRECTS=5 EGG_TLS_WANT_STATUS=302
fetch 'https: a loop, as far as allowed' EGG_TLS_URL="$u/loop" EGG_TLS_REDIRECTS=3 EGG_TLS_WANT_STATUS=302
printf 'https: a CA not trusted: '
EGG_TLS_CA="$dir/other.pem" EGG_TLS_URL="$u/file/big.bin" EGG_TLS_EXPECT=UnknownIssuer ./build/test/live_https
stop
