import socketserver


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            payload = self.request.recv(4096)
            if not payload:
                return
            self.request.sendall(payload)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with EchoServer(("0.0.0.0", 8080), EchoHandler) as server:
    server.serve_forever()
