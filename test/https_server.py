"""An HTTPS server for test/live.sh to fetch from through tls/https.

    python3 test/https_server.py PORT CERT KEY DIR [HTTP_PORT]

Serves, with Content-Length:
  /file/NAME   DIR/NAME as it is
  /headers     the request's headers, as they came
  /redirect    302 to /file/big.bin
  /see-other   303 to /headers (a POST becomes a GET)
  /absolute    301 to https://localhost:PORT/headers
  /other-host  302 to https://127.0.0.1:PORT/headers (another origin)
  /to-http     302 to http://127.0.0.1:HTTP_PORT/ (a downgrade)
  /loop        302 to /loop
Python's standard library only. It prints "ready" once it listens.
"""
import http.server
import os
import ssl
import sys

port, cert, key, root = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
http_port = int(sys.argv[5]) if len(sys.argv) > 5 else 1


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send(self, status, body=b"", location=None):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        p = self.path.split("?")[0]
        if p.startswith("/file/"):
            name = os.path.basename(p[len("/file/"):])
            with open(os.path.join(root, name), "rb") as f:
                self.send(200, f.read())
        elif p == "/headers":
            lines = [f"{self.command} {self.path}"] + [f"{k}: {v}" for k, v in self.headers.items()]
            head = "\r\n".join(lines).encode()
            self.send(200, head)
        elif p == "/redirect":
            self.send(302, location="/file/big.bin")
        elif p == "/see-other":
            self.send(303, location="/headers")
        elif p == "/absolute":
            self.send(301, location=f"https://localhost:{port}/headers")
        elif p == "/other-host":
            self.send(302, location=f"https://127.0.0.1:{port}/headers")
        elif p == "/to-http":
            self.send(302, location=f"http://127.0.0.1:{http_port}/")
        elif p == "/loop":
            self.send(302, location="/loop")
        else:
            self.send(404, b"not found")

    do_GET = do_POST = do_HEAD = answer

    def log_message(self, format, *args):
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(cert, key)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
