#!/bin/sh
# Runs test/live.egg against `openssl s_server`, once for each TLS 1.3
# cipher suite, on a throwaway self-signed certificate (the client does
# not check certificates yet). Needs OpenSSL 1.1.1 or later.
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
"$CLUTCH" test live >/dev/null    # builds it; without the variables it only returns
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/key.pem" -out "$dir/cert.pem" -subj /CN=localhost -days 1 2>/dev/null
for suite in TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384; do
    openssl s_server -quiet -www -tls1_3 -accept "$PORT" -cert "$dir/cert.pem" \
        -key "$dir/key.pem" -ciphersuites "$suite" -groups X25519 >"$dir/server.log" 2>&1 &
    pid=$!
    wait_port
    EGG_TLS_PORT=$PORT EGG_TLS_SUITE=$suite ./build/test/live
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    pid=
done
# A server that takes only P-256: the client's second key share.
openssl s_server -quiet -www -tls1_3 -accept "$PORT" -cert "$dir/cert.pem" \
    -key "$dir/key.pem" -groups P-256 >"$dir/server.log" 2>&1 &
pid=$!
wait_port
printf 'P-256 key share: '
EGG_TLS_PORT=$PORT EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 ./build/test/live
kill "$pid"
wait "$pid" 2>/dev/null || true
pid=
# A file of 1 MiB: 64 full records and more, through s_server -HTTP.
head -c 1048576 /dev/urandom >"$dir/big.bin"
(cd "$dir" && exec openssl s_server -quiet -HTTP -tls1_3 -accept "$PORT" -cert cert.pem \
    -key key.pem >server.log 2>&1) &
pid=$!
wait_port
EGG_TLS_PORT=$PORT EGG_TLS_SUITE=TLS_CHACHA20_POLY1305_SHA256 \
    EGG_TLS_SHA256=$(openssl dgst -sha256 -r "$dir/big.bin" | cut -d' ' -f1) ./build/test/live
