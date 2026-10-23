import base64
import hashlib
import socketserver
import struct
import time
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WebHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif path == "/allowed":
            body = (
                f"user={self.headers.get('X-Limen-User', '')}\n"
                f"roles={self.headers.get('X-Limen-Roles', '')}\n"
                f"assertion={self.headers.get('X-Limen-Identity', '')}\n"
                f"cookie={self.headers.get('Cookie', '')}\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "fixture_session=owned-by-app; Path=/; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/stream":
            body = b"chunk-one\nchunk-two\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(b"chunk-one\n")
            self.wfile.flush()
            time.sleep(0.8)
            self.wfile.write(b"chunk-two\n")
            self.wfile.flush()
        elif path == "/ws":
            self.websocket()
        else:
            self.send_error(404)

    def websocket(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key or self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_error(400)
            return
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        self.send_response_only(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        first = self.rfile.read(2)
        if len(first) != 2:
            return
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.rfile.read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.rfile.read(8))[0]
        mask = self.rfile.read(4) if first[1] & 0x80 else b""
        payload = self.rfile.read(length)
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.connection.sendall(bytes([0x81, len(payload)]) + payload)

    def log_message(self, _format, *_args):
        return


class WebServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


with WebServer(("0.0.0.0", 8080), WebHandler) as server:
    server.serve_forever()
