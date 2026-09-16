#!/usr/bin/env python3
"""假服务器 v3 — 记录二进制发出的所有请求（headers + body），passport 端返回可解析响应。"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = "/tmp/fake3.log"

def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        log(f"=== {time.strftime('%H:%M:%S')} {self.command} {self.path} ===")
        for k, v in self.headers.items():
            log(f"  H {k}: {v}")
        if body:
            log(f"  BODY[{len(body)}]: {body.decode('utf-8', 'replace')}")
        log("")
        # —— 响应 ——
        if self.path.startswith("/v6/user/login") or self.path.startswith("/v6/user/phoneCodeLogin"):
            self._send({"code": 0, "msg": "success", "data": {
                "access_token": "FAKE_ACCESS_TOKEN_123",
                "refresh_token": "FAKE_REFRESH_TOKEN_456",
                "accessTokenValidity": "3600",
                "scope": "",
                "token_type": "Bearer",
                "uid": "FAKE_UID_1",
                "uuid": "FAKE_UUID_1",
                "business_uid": "FAKE_BIZ_UID_789",
                "token": "FAKE_BIZ_TOKEN_ABC",
                "loginToken": "FAKE_BIZ_TOKEN_ABC",
                "businessToken": "FAKE_BIZ_TOKEN_ABC",
                "resultCode": 0,
                "resultDesc": "success",
                "data": {"token": "FAKE_BIZ_TOKEN_ABC", "business_uid": "FAKE_BIZ_UID_789"},
            }})
        elif self.path.startswith("/v6/user/login/v4/code/phone"):
            self._send({"code": 0, "msg": "success", "data": {"resultCode": 0}})
        elif self.path.startswith("/v5/user"):
            self._send({"code": 0, "data": {"status": "ok", "uid": "FAKE_UID_1"}})
        elif self.path.startswith("/v3/user/refresh"):
            self._send({"code": 0, "data": {
                "access_token": "FAKE_ACCESS_TOKEN_456",
                "refresh_token": "FAKE_REFRESH_TOKEN_456",
                "accessTokenValidity": "3600",
            }})
        else:
            # business/travel 加密端点：无法解密响应，返回占位 JSON（调用会报错，但请求已记录）
            self._send({"code": 0, "msg": "ok", "data": {"r": ""}})

    def _send(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    open(LOG, "w").close()
    print(f"fake server on :{port}, log -> {LOG}")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
