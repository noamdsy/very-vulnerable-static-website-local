#!/usr/bin/env python3
"""
Local static server for the NexaCloud vulnerable test target.

Usage:
    python serve.py                  # http://127.0.0.1:8099  (loopback only)
    python serve.py 9000             # custom port, loopback only
    python serve.py 8099 0.0.0.0     # bind all interfaces (reachable from Docker
                                     # via host.docker.internal:8099 — e.g. Strix)

localhost / 127.0.0.1 is a "secure context", so window.crypto.subtle works over
plain HTTP there. When reached from another origin (e.g. host.docker.internal),
the app falls back to an in-page HMAC, so JWT signing/verification still works.
Point your scanner / agent at the printed URL. Ctrl+C to stop.
"""
import http.server
import socketserver
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"


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
    all_ifaces = HOST in ("0.0.0.0", "::", "")
    local_host = "127.0.0.1" if all_ifaces else HOST
    local_url = "http://%s:%d/" % (local_host, PORT)
    with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
        print("NexaCloud test target serving at:")
        print("    " + local_url + "   (this machine)")
        if all_ifaces:
            print("    http://host.docker.internal:%d/   (from Docker, e.g. Strix)" % PORT)
            print("    Bound to all interfaces — reachable on your LAN. Stop it when done.")
        print("Serving folder: %s" % ROOT)
        print("Press Ctrl+C to stop.\n")
        try:
            webbrowser.open(local_url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
