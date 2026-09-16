#!/usr/bin/env python3
"""九号出行（Ninebot）纯 Python API 客户端 —— 不依赖 ninecli 二进制。

2026-08-07 从 ninecli v0.1.7 二进制反汇编 + GDB 断点取证 + 假服务器抓包还原，
全部请求结构经真实抓包逐字节验证（见 docs/api-recon.md 与 MEMORY.md）。

链路：
  passport 登录（明文 + Sign 签名）→ business 登录（网易加密层）→
  vehicles / travel-list / travel-info（加密请求/解密响应）

用法示例：
  python3 ninebot_api.py login -u <手机号> -p <密码>          # 登录并保存 tokens.json
  python3 ninebot_api.py vehicles                             # 车辆列表
  python3 ninebot_api.py travel <SN> --month 202607           # 行程列表
  python3 ninebot_api.py travel <SN> --detail <travel_id>     # 行程详情
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

try:
    import ninebot_crypto as crypto
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ninebot_crypto as crypto

# ---------------------------------------------------------------------------
# 常量（抓包确认）
# ---------------------------------------------------------------------------

PASSPORT_BASE = "https://api-passport-bj.ninebot.com"
BIZ_BASE = "https://api-jhcx-v6-bj.ninebot.com"
TRAVEL_BASE = "https://cn-cbu-gateway.ninebot.com"
EBIKE_BASE = "https://ebike.ninebot.com"
STEELDUST_BASE = "https://steeldust.ninebot.com"

CLIENT_VER = "610063322"          # Client-Ver / client_ver / current_version
APP_VERSION = "610063322"         # passport App_version
OS_VERSION = "13"
OS_MODEL = "Xiaomi"               # config.json os_model
PLATFORM_VER = "13 Xiaomi"        # = os_version + " " + os_model
RN_VERSION = "743"                # rnVersion / Rn-Ver
CLIENT_KEY = "e177176a-3b3e-1513-e26e-d1123034cb66"  # passport clientKey

PATH_PASSPORT_LOGIN = "/v6/user/login"
PATH_PASSPORT_REFRESH = "/v3/user/refresh"
PATH_BIZ_LOGIN = "/user/user/login"
PATH_VEHICLES = "/vehicle/binding/my-vehicle"
PATH_TRAVEL_LIST = "/app-api/travel/v6/travel-list2"
PATH_TRAVEL_INFO = "/app-api/travel/v6/travel-info"

# 公共参数顺序（GDB 抓包：business login / vehicles / travel 完全一致的前 11 个字段）
COMMON_PARAMS = [
    ("sys_language", "zh-hans-cn"),
    ("client_ver", CLIENT_VER),
    ("device_id", None),          # 来自 config
    ("regionx", "bj"),
    ("language", "zh"),
    ("ostype", "and"),
    ("lang", "zh"),
    ("platform_ver", PLATFORM_VER),
    ("platform", "android"),
    ("login_country", "CN"),
]

# ---------------------------------------------------------------------------
# 配置 / token 持久化（兼容 ninecli 的 config.json / tokens.json）
# ---------------------------------------------------------------------------

def default_config_dir():
    return os.environ.get("NINEBOT_CONFIG_DIR", str(Path.home() / ".config" / "ninebot"))


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default if default is not None else {}


def save_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_config(config_dir):
    cfg = load_json(Path(config_dir) / "config.json")
    if not cfg.get("device_id"):
        cfg["device_id"] = secrets.token_hex(16)
        save_json(Path(config_dir) / "config.json", cfg)
    return cfg


def load_tokens(config_dir):
    return load_json(Path(config_dir) / "tokens.json")


def save_tokens(config_dir, tokens):
    tokens["saved_at"] = int(time.time())
    save_json(Path(config_dir) / "tokens.json", tokens)


# ---------------------------------------------------------------------------
# Passport（明文 + Sign）
# ---------------------------------------------------------------------------

def passport_sign(url: str, params: dict) -> str:
    """PassportSign：sha256(排序后 k=v&k=v)。params 含 app_version/areaCode/device/
    os/os_language/os_version/password/timestamp/url/username（clientKey 自动补）。"""
    params = dict(params)
    params["clientKey"] = CLIENT_KEY
    params["url"] = url
    canonical = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _passport_post(base, path, body: dict, extra_headers=None) -> dict:
    url = base.rstrip("/") + path
    headers = {
        "App_version": APP_VERSION,
        "Clientid": "vehicle_app_prod",
        "Content-Type": "application/json; charset=UTF-8",
        "Os": "Android",
        "Os_language": "zh-hans-cn",
        "Os_version": OS_VERSION,
        "Accept-Encoding": "gzip",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=json.dumps(body, separators=(",", ":")).encode(),
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def passport_login(username: str, password: str, area_code="86",
                   device="ANDROID", base=PASSPORT_BASE) -> dict:
    """密码登录 -> {access_token, refresh_token, uuid, ...}"""
    ts = int(time.time() * 1000)
    body = {"areaCode": area_code, "device": device, "password": password, "username": username}
    sign_params = {
        "app_version": APP_VERSION, "areaCode": area_code, "device": device,
        "os": "Android", "os_language": "zh-hans-cn", "os_version": OS_VERSION,
        "password": password, "timestamp": str(ts), "url": PATH_PASSPORT_LOGIN,
        "username": username,
    }
    headers = {
        "Timestamp": str(ts),
        "Sign": passport_sign(PATH_PASSPORT_LOGIN, sign_params),
    }
    resp = _passport_post(base, PATH_PASSPORT_LOGIN, body, headers)
    if resp.get("code") != 0:
        raise RuntimeError(f"passport login failed: code={resp.get('code')} msg={resp.get('msg')}")
    data = resp.get("data") or {}
    if not data.get("access_token"):
        raise RuntimeError(f"passport login: missing access_token in response: {resp}")
    return {
        "uuid": data.get("uuid", ""),
        "username": username,
        "phone": data.get("phone", ""),
        "region": data.get("region", ""),
        "areaCode": area_code,
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", ""),
        "accessTokenValidity": str(data.get("accessTokenValidity", "")),
    }


def passport_refresh(tokens: dict, base=PASSPORT_BASE) -> dict:
    """token 过期刷新（POST /v3/user/refresh）"""
    ts = int(time.time() * 1000)
    body = {"accessToken": tokens["access_token"], "device": "ANDROID",
            "refreshToken": tokens["refresh_token"]}
    sign_params = {
        "accessToken": body["accessToken"], "app_version": APP_VERSION, "device": "ANDROID",
        "os": "Android", "os_language": "zh-hans-cn", "os_version": OS_VERSION,
        "refreshToken": body["refreshToken"], "timestamp": str(ts), "url": PATH_PASSPORT_REFRESH,
    }
    headers = {
        "Timestamp": str(ts),
        "Sign": passport_sign(PATH_PASSPORT_REFRESH, sign_params),
    }
    resp = _passport_post(base, PATH_PASSPORT_REFRESH, body, headers)
    if resp.get("code") != 0:
        raise RuntimeError(f"passport refresh failed: code={resp.get('code')} desc={resp.get('desc')}")
    data = resp.get("data") or {}
    tokens = dict(tokens)
    tokens["access_token"] = data.get("access_token", tokens["access_token"])
    tokens["refresh_token"] = data.get("refresh_token", tokens["refresh_token"])
    if data.get("accessTokenValidity"):
        tokens["accessTokenValidity"] = str(data["accessTokenValidity"])
    return tokens


def tokens_valid(tokens: dict) -> bool:
    """accessTokenValidity 是毫秒绝对时间戳；过期则需刷新/重登"""
    if not tokens or not tokens.get("access_token"):
        return False
    try:
        expiry = int(tokens.get("accessTokenValidity", 0))
    except ValueError:
        return False
    if not expiry:
        return False
    return expiry / 1000.0 > time.time() + 60


# ---------------------------------------------------------------------------
# Business 层（网易加密）
# ---------------------------------------------------------------------------

def _business_headers(access_token: str = None, business_type=0, extra=None) -> dict:
    h = {
        "User-Agent": "okhttp/4.9.1",
        "Accept-Encoding": "gzip",
        "Business-Type": str(business_type),
        "Cache-Control": "no-cache",
        "Client-Ver": CLIENT_VER,
        "Content-Type": "text/html;charset=UTF-8",
        "Debug": "0",
        "Device-Id": None,          # 调用方填 config.device_id
        "Language": "zh",
        "Login-Country": "CN",
        "Need_decrypt": "1",
        "Ninebot-Version": "2",
        "Platform": "Android",
        "Platform-Ver": OS_VERSION,
        "Regionx": "bj",
        "Request-Id": secrets.token_hex(16),
        "Service-Time": str(int(time.time() * 1000)),
        "Sys-Language": "zh-hans-cn",
    }
    if access_token:
        h["Access_token"] = access_token
        h["Accept"] = "application/json"
        h["Rn-Module"] = "Track"
        h["Rn-Ver"] = RN_VERSION
        h["Rn-Version"] = "0"
    if extra:
        h.update(extra)
    return h


def _common_params(device_id: str) -> dict:
    return dict((k, (v if v is not None else device_id)) for k, v in COMMON_PARAMS)


def _send_encrypted(host, path, inner_params: dict, device_id: str,
                    access_token=None, business_type=0, timeout=60) -> dict:
    """构造加密请求、发送、解密响应，返回内层 JSON（{code, data, ...}）"""
    inner = crypto.build_inner(inner_params)
    body, sec = crypto.build_request(inner.encode())
    headers = _business_headers(access_token, business_type)
    headers["Device-Id"] = device_id
    req = urllib.request.Request(host.rstrip("/") + path,
                                 data=json.dumps(body, separators=(",", ":")).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"business {path}: HTTP {e.code}: {e.read()[:200]}")
    try:
        outer = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise RuntimeError(f"business {path}: 非 JSON 响应: {raw[:200]!r}")
    # wire 层响应 = {"r": b64}；业务 code/data/message 在解密后的内层
    if not isinstance(outer, dict) or not isinstance(outer.get("r"), str) or not outer["r"]:
        raise RuntimeError(f"business {path}: 响应缺少 r 字段: {raw[:200]!r}")
    plain = crypto.decrypt_wire_response(outer, sec)
    try:
        inner_resp = json.loads(plain.decode("utf-8"))
    except ValueError:
        raise RuntimeError(f"business {path}: 解密后非 JSON: {plain[:200]!r}")
    return inner_resp


def business_login(tokens: dict, device_id: str, base=BIZ_BASE, region="bj") -> str:
    """business 登录 -> business_uid（写入 tokens 并返回）

    内层字段顺序（抓包）：公共参数 + access_token/uuid/token/refresh_token/region/
    serviceTime/nonce(+checkcode)
    """
    now_ms = int(time.time() * 1000)
    params = _common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uuid": tokens.get("uuid", ""),
        "token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "region": region,
        "serviceTime": now_ms,
        "nonce": crypto.gen_nonce(),
    })
    resp = _send_encrypted(base, PATH_BIZ_LOGIN, params, device_id, business_type=0)
    if resp.get("code") != 0:
        raise RuntimeError(f"business_login: server code={resp.get('code')} message={resp.get('message')!r}")
    data = resp.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("business_login: missing data field in response")
    uid = data.get("uid")
    if not uid:
        raise RuntimeError("business_login: missing uid in response data")
    tokens["business_uid"] = str(uid)
    return str(uid)


def vehicles(tokens: dict, device_id: str, base=EBIKE_BASE,
             vehicle_type="64", timeout=60) -> list:
    """车辆列表（内层：公共参数 + access_token/uid/vehicle_type/serviceTime/nonce）

    返回车辆 dict 列表（含 wnumber 等字段）。
    vehicle_type=64 为 GDB 抓包实测值（二进制默认发送）。"""
    now_ms = int(time.time() * 1000)
    params = _common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uid": tokens.get("business_uid", ""),
        "vehicle_type": vehicle_type,
        "serviceTime": now_ms,
        "nonce": crypto.gen_nonce(),
    })
    resp = _send_encrypted(base, PATH_VEHICLES, params, device_id,
                           access_token=tokens["access_token"], business_type=2, timeout=timeout)
    if resp.get("code") != 0:
        raise RuntimeError(f"vehicles: server code={resp.get('code')} message={resp.get('message')!r}")
    data = resp.get("data")
    if isinstance(data, dict):
        lst = data.get("vehicles") or data.get("list") or []
    elif isinstance(data, list):
        lst = data
    else:
        lst = []
    return lst


def travel_list(tokens: dict, device_id: str, wnumber: str, month: str,
                base=TRAVEL_BASE, vehicle_type="112", page="1", timeout=60) -> dict:
    """月度行程列表（内层：公共参数 + access_token/uid/wnumber/rnVersion/vehicle_type/
    month/page/current_version/serviceTime/nonce）

    返回内层 data 字段（{list: [...], total_mileages, ...}）。"""
    now_ms = int(time.time() * 1000)
    params = _common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uid": tokens.get("business_uid", ""),
        "wnumber": wnumber,
        "rnVersion": RN_VERSION,
        "vehicle_type": vehicle_type,
        "month": month,
        "page": page,
        "current_version": CLIENT_VER,
        "serviceTime": now_ms,
        "nonce": crypto.gen_nonce(),
    })
    resp = _send_encrypted(base, PATH_TRAVEL_LIST, params, device_id,
                           access_token=tokens["access_token"], business_type=2, timeout=timeout)
    if resp.get("code") != 0:
        raise RuntimeError(f"travel: server code={resp.get('code')} message={resp.get('message')!r}")
    data = resp.get("data")
    return data if isinstance(data, dict) else {}


def travel_detail(tokens: dict, device_id: str, wnumber: str, travel_id: str,
                  base=TRAVEL_BASE, vehicle_type="112", timeout=60) -> dict:
    """单次行程详情（内层：公共参数 + access_token/uid/wnumber/rnVersion/vehicle_type/
    travel_id/current_version/serviceTime/nonce）

    返回内层 data 字段（{travel_details / track / ...}）。"""
    now_ms = int(time.time() * 1000)
    params = _common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uid": tokens.get("business_uid", ""),
        "wnumber": wnumber,
        "rnVersion": RN_VERSION,
        "vehicle_type": vehicle_type,
        "travel_id": travel_id,
        "current_version": CLIENT_VER,
        "serviceTime": now_ms,
        "nonce": crypto.gen_nonce(),
    })
    resp = _send_encrypted(base, PATH_TRAVEL_INFO, params, device_id,
                           access_token=tokens["access_token"], business_type=2, timeout=timeout)
    if resp.get("code") != 0:
        raise RuntimeError(f"travel detail: server code={resp.get('code')} message={resp.get('message')!r}")
    data = resp.get("data")
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# 高层：登录编排
# ---------------------------------------------------------------------------

def ensure_login(config_dir=None, username=None, password=None, **hosts) -> dict:
    """确保有可用 token；必要时 passport 登录 + business 登录。

    返回 tokens dict（含 business_uid）。"""
    config_dir = config_dir or default_config_dir()
    cfg = load_config(config_dir)
    tokens = load_tokens(config_dir)
    if tokens_valid(tokens) and tokens.get("business_uid"):
        return tokens
    if not tokens_valid(tokens) and username and password:
        tokens = passport_login(username, password)
        save_tokens(config_dir, tokens)
    if not tokens_valid(tokens):
        raise RuntimeError("token 缺失或过期：请先 python3 ninebot_api.py login -u <手机号> -p <密码>")
    # 尝试刷新过期 token
    if not tokens_valid(tokens) and tokens.get("refresh_token"):
        try:
            tokens = passport_refresh(tokens, base=hosts.get("passport", PASSPORT_BASE))
            save_tokens(config_dir, tokens)
        except Exception as e:
            print(f"[!] token 刷新失败：{e}", file=sys.stderr)
    if not tokens.get("business_uid"):
        uid = business_login(tokens, cfg["device_id"], base=hosts.get("biz", BIZ_BASE))
        save_tokens(config_dir, tokens)
    return tokens


# ---------------------------------------------------------------------------
# 自测（无账号即可验证全链路；签名/加密/解密均与 ninecli 抓包对齐）
# ---------------------------------------------------------------------------

def self_test():
    import base64 as _b64
    ok = []

    # 1) Passport Sign 固定向量（GDB 抓包 canonical）
    params = {"app_version": "610063322", "areaCode": "86", "device": "ANDROID",
              "os": "Android", "os_language": "zh-hans-cn", "os_version": "13",
              "password": "endtoendpw1", "timestamp": "1786095783403",
              "url": "/v6/user/login", "username": "e2etest"}
    sig = passport_sign("/v6/user/login", params)
    # 用 GDB 抓包验证：canonical = app_version=610063322&areaCode=86&clientKey=...&...
    expect_canonical = ("app_version=610063322&areaCode=86&clientKey=e177176a-3b3e-1513-"
                        "e26e-d1123034cb66&device=ANDROID&os=Android&os_language=zh-hans-cn"
                        "&os_version=13&password=endtoendpw1&timestamp=1786095783403"
                        "&url=/v6/user/login&username=e2etest")
    assert sig == hashlib.sha256(expect_canonical.encode()).hexdigest(), sig
    ok.append("passport_sign 固定向量 ✓")

    # 2) 加密请求构造 + 模拟服务器响应解密（全链路）
    device_id = secrets.token_hex(16)
    tokens = {"access_token": "AT", "refresh_token": "RT", "uuid": "U",
              "business_uid": "BID"}
    params = _common_params(device_id)
    params.update({"access_token": "AT", "uid": "BID", "vehicle_type": "65",
                   "serviceTime": int(time.time() * 1000), "nonce": crypto.gen_nonce()})
    inner = crypto.build_inner(params)
    body, sec = crypto.build_request(inner.encode())
    assert set(body) == {"d", "h", "k", "p", "t"}
    # 模拟服务器：用请求里的 kd 派生响应密钥，构造 wrapper 明文（2026-08-07 实测二进制格式）
    resp_key = crypto.derive_key(sec["kd1"].encode(), sec["kd2"].encode(),
                                 sec["kd3"].encode(), sec["kd4"].encode())
    biz = json.dumps({"code": 0, "data": {"vehicles": [{"wnumber": "NB1"}]}},
                     separators=(",", ":")).encode()
    resp_wrapper = json.dumps({"data": crypto.android_b64(biz), "platform": 2,
                               "timeStamp": int(time.time())}).encode()
    fake_r = {"r": _b64.b64encode(crypto._aes_cbc_encrypt(resp_key, resp_wrapper)).decode()}
    plain = crypto.decrypt_wire_response(fake_r, sec)
    assert json.loads(plain)["data"]["vehicles"][0]["wnumber"] == "NB1"
    ok.append("加密请求 + 响应解密 全链路 ✓ (wire=%s)" % {k: (v[:12] + "…") for k, v in body.items()})

    # 3) 请求头完整性
    h = _business_headers("AT", 2)
    h["Device-Id"] = device_id  # 正常由 _send_encrypted 填充
    for k in ("Business-Type", "Client-Ver", "Device-Id", "Need_decrypt",
              "Request-Id", "Service-Time", "Access_token", "Rn-Module"):
        assert k in h and h[k], k
    assert h["Business-Type"] == "2" and h["Rn-Module"] == "Track"
    ok.append("请求头构造 ✓ (%d 个头)" % len(h))

    print("=== ninebot_api 自测通过 ===")
    for line in ok:
        print("  " + line)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="九号出行纯 Python 客户端")
    ap.add_argument("--config", default=default_config_dir())
    ap.add_argument("--passport-base", default=PASSPORT_BASE)
    ap.add_argument("--biz-host", default=BIZ_BASE)
    ap.add_argument("--travel-host", default=TRAVEL_BASE)
    ap.add_argument("--ebike-host", default=EBIKE_BASE)
    ap.add_argument("--self-test", action="store_true", help="全链路自测（无需账号）")
    sub = ap.add_subparsers(dest="cmd")

    p_login = sub.add_parser("login", help="密码登录（passport + business）")
    p_login.add_argument("-u", "--username", required=True)
    p_login.add_argument("-p", "--password", required=True)

    sub.add_parser("vehicles", help="车辆列表")

    p_travel = sub.add_parser("travel", help="行程列表/详情")
    p_travel.add_argument("sn")
    p_travel.add_argument("--month", default=datetime.now().strftime("%Y%m"))
    p_travel.add_argument("--detail")

    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    hosts = {"passport": args.passport_base, "biz": args.biz_host,
             "travel": args.travel_host, "ebike": args.ebike_host}

    if args.cmd == "login":
        tokens = passport_login(args.username, args.password, base=hosts["passport"])
        save_tokens(args.config, tokens)
        print(f"[+] passport 登录成功 uuid={tokens.get('uuid')}")
        try:
            cfg = load_config(args.config)
            uid = business_login(tokens, cfg["device_id"], base=hosts["biz"])
            save_tokens(args.config, tokens)
            print(f"[+] business 登录成功 business_uid={uid}")
        except Exception as e:
            print(f"[!] business 登录失败（token 已保存，稍后会自动重试）：{e}", file=sys.stderr)
        return

    tokens = ensure_login(args.config, **hosts)
    cfg = load_config(args.config)
    device_id = cfg["device_id"]

    if args.cmd == "vehicles":
        lst = vehicles(tokens, device_id, base=hosts["ebike"])
        print(json.dumps(lst, ensure_ascii=False, indent=1))
    elif args.cmd == "travel":
        if args.detail:
            resp = travel_detail(tokens, device_id, args.sn, args.detail, base=hosts["travel"])
        else:
            resp = travel_list(tokens, device_id, args.sn, args.month, base=hosts["travel"])
        print(json.dumps(resp, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
