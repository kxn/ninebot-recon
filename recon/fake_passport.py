#!/usr/bin/env python3
"""本地假 Passport 服务器 — 审计 ninecli 登录时的网络行为。
监听 127.0.0.1:18080，把所有请求原样记录到 /tmp/fake_passport.log。
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = "/tmp/fake_passport.log"

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _log(self, body=None):
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"=== {self.command} {self.path} ===\n")
            for k, v in self.headers.items():
                f.write(f"  H {k}: {v}\n")
            if body:
                f.write(f"  BODY: {body[:2000]}\n")
            f.write("\n")

    def _send(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self._log(body)
        # 假装登录成功，返回一个假 token（结构按 Passport 惯例）
        self._send({
            "code": 0,
            "msg": "success",
            "data": {
                "access_token": "FAKE_ACCESS_TOKEN_123",
                "refresh_token": "FAKE_REFRESH_TOKEN_456",
                "accessTokenValidity": "3600",
                "scope": "",
                "token_type": "Bearer",
            },
        })

    def do_GET(self):
        self._log()
        self._send({"code": 0, "data": {"status": "ok"}})

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 18080), H).serve_forever()
