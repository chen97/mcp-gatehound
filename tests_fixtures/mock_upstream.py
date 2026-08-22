#!/usr/bin/env python3
"""A tiny REST service the gateway can front, for testing `proxy` actions end to end.

    python3 tests_fixtures/mock_upstream.py 23399

It is deliberately dull: a handful of notes behind a bearer token, plus an endpoint that
reports what it received, so a test can prove a call reached the upstream exactly once.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

TOKEN = "tok"

NOTES = {
    "welcome": {"id": "welcome", "title": "Welcome", "body": "The first note."},
    "shopping": {"id": "shopping", "title": "Shopping", "body": "Oat milk, bread."},
    # An identifier carrying characters that are legal in a path segment but easy to get
    # wrong: the gateway must pass them through without mangling or double-encoding.
    "!odd:host.local": {"id": "!odd:host.local", "title": "Odd id", "body": "Still fine."},
}

WRITES = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._json(401, {"error": "bad token"})
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/healthz":
            return self._json(200, {"ok": True})
        if url.path == "/__mock/writes":
            return self._json(200, {"writes": WRITES})
        if not self._authorized():
            return
        if url.path == "/v1/notes":
            limit = int(parse_qs(url.query).get("limit", ["100"])[0])
            return self._json(200, {"items": list(NOTES.values())[:limit]})
        if url.path.startswith("/v1/notes/"):
            note_id = unquote(url.path[len("/v1/notes/"):])
            if note_id in NOTES:
                return self._json(200, NOTES[note_id])
            return self._json(404, {"error": "no such note"})
        return self._json(404, {"error": "unknown " + url.path})

    def do_POST(self):
        url = urlparse(self.path)
        if not self._authorized():
            return
        if url.path.startswith("/v1/notes/"):
            note_id = unquote(url.path[len("/v1/notes/"):])
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            WRITES.append({"id": note_id, "body": body.get("body")})
            return self._json(200, {"ok": True, "id": note_id, "revision": len(WRITES)})
        return self._json(404, {"error": "unknown " + url.path})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 23399
    print("mock upstream listening on", port, flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
