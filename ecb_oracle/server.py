#!/usr/bin/env python3

import os
import socketserver
import sys

listen_port, chal_file_name = sys.argv[1:]
with open(chal_file_name) as f:
    code = compile(f.read(), chal_file_name, "exec")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        for fd in range(3):
            os.dup2(self.request.fileno(), fd)
        exec(code, {})

    def finish(self):
        sys.stdout.flush()


srv = socketserver.ForkingTCPServer(("0.0.0.0", int(listen_port)), Handler)
srv.serve_forever()
