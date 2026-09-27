#!/usr/bin/env python3
"""
Local static server for the NexaCloud vulnerable test target.

Usage:
    python serve.py            # serves on http://127.0.0.1:8099
    python serve.py 9000       # serves on http://127.0.0.1:9000

localhost is a "secure context", so window.crypto.subtle (used by the app's
JWT signing/verification) works over plain HTTP — no TLS needed.
Point your scanner / agent at the printed URL. Ctrl+C to stop.
"""
import http.server
import socketserver
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
HOST = "127.0.0.1"


class Handler(http.server.SimpleHTTPRequestHandler):
    # Serve everything relative to this script's folder, not the CWD.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    # Explicit MIME types so app.js / app.js.map load correctly on any OS.
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
        ".css": "text/css",
        ".html": "text/html",
        ".json": "application/json",
        ".map": "application/json",
        ".svg": "image/svg+xml",
    }

    def end_headers(self):
        # No caching, so edits to the files show up on the next reload.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stdout.write("  %s - %s\n" % (self.address_string(), fmt % args))


def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
        url = "http://%s:%d/" % (HOST, PORT)
        print("NexaCloud test target serving at:")
        print("    " + url)
        print("Serving folder: %s" % ROOT)
        print("Press Ctrl+C to stop.\n")
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
