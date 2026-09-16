#!/usr/bin/env python3
"""假服务器 v4 — 能返回「合法加密响应」，让二进制一路走到 travel-list。

原理：business/travel 请求的 wrapper 明文由 GDB 在 AES 加密前抓到
(/tmp/wrapper_latest.bin，含 kd1..kd4 + AndroidB64 内层)。假服务器收到
加密请求时，读最新 wrapper 提取 kd1..kd4，用 ninebot_crypto 复算
DeriveKey 构造加密响应 {"r": b64(AES-CBC(业务JSON))} —— 二进制能正常解密。
"""
import base64
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = "/tmp/fake4.log"
WRAPPER = "/tmp/wrapper_latest.bin"

sys.path.insert(0, "/data/dl/ninebot")
import ninebot_crypto as crypto


def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def latest_wrapper():
    """读最新 GDB 抓的 wrapper 明文，返回 kd1..4 + 内层 JSON dict。"""
    for _ in range(50):  # 最多等 5s（GDB 断点可能刚命中）
        try:
            st = os.stat(WRAPPER)
            if time.time() - st.st_mtime < 10:
                raw = open(WRAPPER, "rb").read().decode("utf-8", "replace")
                w = json.loads(raw)
                inner_b64 = w.get("data", "").strip()
                inner = json.loads(base64.b64decode(inner_b64).decode("utf-8"))
                return w, inner
        except Exception:
            pass
        time.sleep(0.1)
    return None, None


def encrypt_biz_response(inner: dict, kd1, kd2, kd3, kd4) -> dict:
    """构造 wire 响应：{"r": b64(AES-CBC(wrapper))}

    wrapper = {"data": AndroidB64(业务JSON), "platform": 2, "timeStamp": 秒}
    —— 二进制 DecryptResponse 解密后解析 wrapper 取 data，与真实服务器一致。
    """
    key = crypto.derive_key(kd1.encode(), kd2.encode(), kd3.encode(), kd4.encode())
    wrapper = {
        "data": crypto.android_b64(json.dumps(inner, separators=(",", ":"), ensure_ascii=False).encode()),
        "platform": 2,
        "timeStamp": int(time.time()),
    }
    ct = crypto._aes_cbc_encrypt(key, json.dumps(wrapper, separators=(",", ":")).encode())
    return {"r": base64.b64encode(ct).decode()}


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

        # —— Passport 明文端点 ——
        if self.path.startswith("/v6/user/login"):
            self._send({"code": 0, "msg": "success", "data": {
                "access_token": "FAKE_ACCESS_TOKEN_123",
                "refresh_token": "FAKE_REFRESH_TOKEN_456",
                "accessTokenValidity": "3600",
                "scope": "", "token_type": "Bearer",
                "uid": "FAKE_UID_1", "uuid": "FAKE_UUID_1",
                "business_uid": "FAKE_BIZ_UID_789",
            }})
        elif self.path.startswith("/v3/user/refresh"):
            self._send({"code": 0, "data": {
                "access_token": "FAKE_ACCESS_TOKEN_456",
                "refresh_token": "FAKE_REFRESH_TOKEN_456",
                "accessTokenValidity": "3600",
            }})
        elif self.path.startswith("/v5/user"):
            self._send({"code": 0, "data": {"status": "ok", "uid": "FAKE_UID_1"}})
        elif self.path.startswith("/v6/user/login/v4/code/phone"):
            self._send({"code": 0, "msg": "success", "data": {"resultCode": 0}})

        # —— business/travel 加密端点 ——
        else:
            w, inner = latest_wrapper()
            if w is None:
                log(f"  !! wrapper 未抓到，无法构造加密响应")
                self._send({"code": 1, "msg": "no wrapper"})
                return
            kd = (w["keyDataOne"], w["keyDataTwo"], w["keyDataThree"], w["keyDataFour"])
            log(f"  !! kd from wrapper: {kd}")

            if self.path.startswith("/user/user/login"):
                biz = {
                    "code": 0, "msg": "success", "message": "success",
                    "data": {
                        "uid": "FAKE_BIZ_UID_789",
                        "business_uid": "FAKE_BIZ_UID_789",
                        "resultCode": 0, "resultDesc": "success",
                        "token": "FAKE_BIZ_TOKEN_ABC",
                        "businessToken": "FAKE_BIZ_TOKEN_ABC",
                        "access_token": "FAKE_ACCESS_TOKEN_456",
                    },
                }
            elif self.path.startswith("/app-api/travel/v6/travel-list"):
                biz = {
                    "code": 0, "msg": "success",
                    "data": {
                        "list": [{
                            # 字段名/类型已从 printTravelGroups.func1 反汇编确认：
                            # end_time_format/mileages/speed/used_electricity/travel_id 是 string，
                            # duration 是数字；end_time_format 取 [11:16] 显示 HH:MM
                            "end_time_format": "2026-08-01 08:30:00",
                            "mileages": "12.5",
                            "duration": 1800,
                            "speed": "45.2",
                            "used_electricity": "8",
                            "travel_id": "T0000000001",
                        }],
                        "total_mileages": "12.5",
                        "total_page": 1,
                        "page": 1,
                    },
                }
            elif self.path.startswith("/app-api/travel/v6/travel-info"):
                biz = {
                    "code": 0, "msg": "success",
                    "data": {
                        "travel_details": [{
                            "travel_id": "T0000000001",
                            "mileage": 12.5,
                            "duration": 1800,
                            "max_speed": 45.2,
                            "avg_speed": 25.0,
                            "track": [],
                        }],
                    },
                }
            elif self.path.startswith("/vehicle/binding/my-vehicle"):
                biz = {
                    "code": 0, "msg": "success",
                    "data": [{
                        "wnumber": "NB1234567890",
                        "vehicle_type": "112",
                        "name": "Fake Scooter",
                        "sn": "NB1234567890",
                    }],
                }
            else:
                biz = {"code": 0, "msg": "ok", "data": {}}
            self._send(encrypt_biz_response(biz, *kd))

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
    print(f"fake server v4 on :{port}, log -> {LOG}, wrapper <- {WRAPPER}")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
