#!/usr/bin/env python3
"""Tiny mock of the Beeper Desktop API and the Anthropic Messages API for local testing.

Run:  python3 tests_fixtures/mock_server.py 23399
Then point the server at it:
  BEEPER_API_URL=http://127.0.0.1:23399 ANTHROPIC_API_URL=http://127.0.0.1:23399
"""
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

SENT = []      # messages the app "sent"
READ = []      # chats marked read
ANTHROPIC_CALLS = 0

NOW = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

CHATS = {
    "!alice:ba_1.local-whatsapp.localhost": {
        "id": "!alice:ba_1.local-whatsapp.localhost", "accountID": "local-whatsapp_ba_1", "network": "WhatsApp",
        "title": "Alice", "type": "single", "unreadCount": 2, "lastActivity": NOW,
        "participants": {"items": [{"id": "u1", "fullName": "Alice"}], "total": 2, "hasMore": False},
    },
    "77": {
        "id": "77", "accountID": "local-telegram_ba_2", "network": "Telegram",
        "title": "Bob", "type": "single", "unreadCount": 1, "lastActivity": NOW,
        "participants": {"items": [{"id": "u2", "fullName": "Bob"}], "total": 2, "hasMore": False},
    },
    "!bot:ba_2.local-telegram.localhost": {
        "id": "!bot:ba_2.local-telegram.localhost", "accountID": "local-telegram_ba_2", "network": "Telegram",
        "title": "Glassnode", "type": "single", "unreadCount": 9, "lastActivity": NOW,
        "participants": {"items": [{"id": "u3", "fullName": "Glassnode", "isNetworkBot": True}], "total": 2, "hasMore": False},
    },
    "!dana:ba_2.local-telegram.localhost": {
        "id": "!dana:ba_2.local-telegram.localhost", "accountID": "local-telegram_ba_2", "network": "Telegram",
        "title": "Dana 小美", "type": "single", "unreadCount": 3, "lastActivity": NOW,
        "participants": {"items": [{"id": "u5", "fullName": "Dana 小美"}], "total": 2, "hasMore": False},
    },
    "!sticker:ba_1.local-whatsapp.localhost": {
        "id": "!sticker:ba_1.local-whatsapp.localhost", "accountID": "local-whatsapp_ba_1", "network": "WhatsApp",
        "title": "Carol", "type": "single", "unreadCount": 1, "lastActivity": NOW,
        "participants": {"items": [{"id": "u4", "fullName": "Carol"}], "total": 2, "hasMore": False},
    },
}

def msg(i, chat, sender, text, mine, ts_offset, mtype="TEXT", atts=None):
    m = {"id": f"m{i}", "chatID": chat, "accountID": "x", "senderID": sender, "senderName": sender,
         "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - ts_offset)),
         "sortKey": str(1_000_000 - ts_offset), "type": mtype, "text": text, "isSender": mine, "isDeleted": False}
    if atts:
        m["attachments"] = atts
    return m

MESSAGES = {
    "!alice:ba_1.local-whatsapp.localhost": [  # newest first, like Beeper
        msg(3, "!alice:ba_1.local-whatsapp.localhost", "Alice", "dinner tonight? 7pm at the usual place", False, 60),
        msg(2, "!alice:ba_1.local-whatsapp.localhost", "Alice", "hey are you free later", False, 120),
        msg(1, "!alice:ba_1.local-whatsapp.localhost", "Me", "ok talk later", True, 3600),
    ],
    "77": [
        msg(12, "77", "Me", "sure, sending it now", True, 30),   # latest is mine -> no draft
        msg(11, "77", "Bob", "can you send the file?", False, 90),
    ],
    "!bot:ba_2.local-telegram.localhost": [
        msg(21, "!bot:ba_2.local-telegram.localhost", "Glassnode", "BTC alert", False, 10),
    ],
    "!dana:ba_2.local-telegram.localhost": [
        msg(43, "!dana:ba_2.local-telegram.localhost", "Dana 小美", "周六的聚会你来吗？大概几点到？", False, 300),
        msg(42, "!dana:ba_2.local-telegram.localhost", "Dana 小美", "<a href=\"https://maps.example/x\">https://maps.example/x</a>", False, 320, "TEXT"),
        msg(41, "!dana:ba_2.local-telegram.localhost", "Me", "好啊 地址发我", True, 4000),
        msg(40, "!dana:ba_2.local-telegram.localhost", "Dana 小美", "我们搬去新家了 周末来玩呀", False, 4100),
    ],
    "!sticker:ba_1.local-whatsapp.localhost": [
        msg(31, "!sticker:ba_1.local-whatsapp.localhost", "Carol", "", False, 20, "IMAGE",
            [{"type": "img", "mimeType": "image/webp", "isSticker": True}]),
        msg(30, "!sticker:ba_1.local-whatsapp.localhost", "Me", "haha ok", True, 200),
    ],
}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if self.headers.get("Authorization") != "Bearer tok":
            return self._json(401, {"error": "bad token"})
        if u.path == "/v1/accounts":
            return self._json(200, {"items": [
                {"accountID": "local-whatsapp_ba_1", "network": "WhatsApp", "user": {"fullName": "Chen"}},
                {"accountID": "local-telegram_ba_2", "network": "Telegram", "user": {"fullName": "Chen"}},
            ]})
        if u.path == "/v1/chats/search":
            items = [c for c in CHATS.values()]
            if q.get("type", ["any"])[0] == "single":
                items = [c for c in items if c["type"] == "single"]
            if q.get("unreadOnly", ["false"])[0] == "true":
                items = [c for c in items if c["unreadCount"] > 0]
            return self._json(200, {"items": items, "hasMore": False})
        if u.path.startswith("/v1/chats/") and u.path.endswith("/messages"):
            cid = unquote(u.path[len("/v1/chats/"):-len("/messages")])
            if cid not in MESSAGES:
                return self._json(404, {"error": "no chat"})
            return self._json(200, {"items": MESSAGES[cid], "hasMore": False})
        if u.path.startswith("/v1/chats/"):
            cid = unquote(u.path[len("/v1/chats/"):])
            if cid in CHATS:
                return self._json(200, CHATS[cid])
            return self._json(404, {"error": "no chat"})
        if u.path == "/__mock/sent":
            return self._json(200, {"sent": SENT, "read": READ, "anthropic_calls": ANTHROPIC_CALLS})
        return self._json(404, {"error": "unknown " + u.path})

    def do_POST(self):
        global ANTHROPIC_CALLS
        u = urlparse(self.path)
        if u.path == "/v1/messages":  # Anthropic mock
            if self.headers.get("x-api-key") != "test-key":
                return self._json(401, {"error": {"message": "bad key"}})
            body = self._body()
            ANTHROPIC_CALLS += 1
            user = body["messages"][0]["content"]
            if "[sticker]" in user:
                text = "[NO_REPLY]"
            elif "Dana" in user and "Additional instruction" not in user:
                text = "来的！我大概七点左右到，要带点什么吗？"
            elif "Additional instruction" in user:
                text = "Sure — 7pm works, see you there."
            else:
                text = "\"yes! 7pm at the usual place works\""
            return self._json(200, {"id": "msg_1", "type": "message", "role": "assistant",
                                    "content": [{"type": "text", "text": text}], "model": body.get("model")})
        if self.headers.get("Authorization") != "Bearer tok":
            return self._json(401, {"error": "bad token"})
        if u.path.startswith("/v1/chats/") and u.path.endswith("/messages"):
            cid = unquote(u.path[len("/v1/chats/"):-len("/messages")])
            body = self._body()
            SENT.append({"chatID": cid, "text": body.get("text")})
            return self._json(200, {"chatID": cid, "pendingMessageID": "m%d" % (900 + len(SENT))})
        if u.path.startswith("/v1/chats/") and u.path.endswith("/read"):
            READ.append(unquote(u.path[len("/v1/chats/"):-len("/read")]))
            return self._json(200, {})
        return self._json(404, {"error": "unknown " + u.path})

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 23399
    print("mock listening on", port, flush=True)
    HTTPServer(("127.0.0.1", port), H).serve_forever()
