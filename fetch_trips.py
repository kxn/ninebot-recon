#!/usr/bin/env python3
"""
九号出行历史行程抓取器（纯 Python 版）
========================================
不再依赖 ninecli 二进制 —— 加密层用 ninebot_crypto.py（公式级逆向），
API 调用用 ninebot_api.py（passport 登录 + business 登录 + vehicles/travel）。

批量拉取历史行程列表 + 单次行程详情，计算 App 隐藏的「最高速度 / 平均速度」，
输出 trips.json / trips.csv 供网页展示。

用法：
  1. 先登录（保存 tokens.json）：
       python3 ninebot_api.py login -u <手机号> -p <密码>
  2. python3 fetch_trips.py            # 全量抓取（默认从 2022-01 到本月）
     python3 fetch_trips.py --from 202401 --to 202412
     python3 fetch_trips.py --sn <车辆SN> --no-detail   # 只要列表、跳过详情

输出：
  trips.json   网页展示用（归一化字段 + 原始数据）
  trips.csv    表格数据
  cache/       原始解密 JSON 缓存（断点续传）
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ninebot_api as api

DEFAULT_CONFIG = os.environ.get("NINEBOT_CONFIG_DIR", str(Path.home() / ".config" / "ninebot"))
CACHE_DIR = Path(__file__).resolve().parent / "cache"
OUT_JSON = Path(__file__).resolve().parent / "trips.json"
OUT_CSV = Path(__file__).resolve().parent / "trips.csv"

# 字段名候选（按优先级；2026-08-07 假服务器 + 二进制实测确认：
# 列表最高速 = "speed"、时间 = "end_time_format"（取 HH:MM）、里程 = "mileages"、
# 时长 = "duration"、耗电 = "used_electricity"、id = "travel_id"）
KEY_ID = ["travel_id", "id", "travelId"]
KEY_START = ["start_time_format", "start_time", "startTime", "begin_time", "beginTime", "time"]
KEY_END = ["end_time_format", "end_time", "endTime", "finish_time", "finishTime"]
KEY_DIST = ["mileages", "mileage", "distance", "total_mileage", "mileage_km"]
KEY_DUR = ["duration", "duration_s", "ride_time", "rideTime", "total_seconds", "seconds", "time_span"]
KEY_USED = ["used_electricity", "electricity", "power_used", "battery_used", "used_power"]
KEY_MAXSPEED = ["speed", "max_speed", "maxSpeed", "top_speed", "topSpeed", "highest_speed", "speed_max", "max"]
KEY_SPEEDS = ["speed_list", "speeds", "speed", "speed_samples", "speedList"]  # 详情里的逐点速度
KEY_TRACK = ["track", "points", "gps", "route", "track_points", "locations", "lat_lng"]


def ensure_login():
    """确保 token 有效；无效则报错提示先登录"""
    try:
        api.ensure_login(CONFIG_DIR)
        return True
    except RuntimeError as e:
        print(f"[!] {e}", file=sys.stderr)
        print("    请先执行：python3 ninebot_api.py login -u <手机号> -p <密码>", file=sys.stderr)
        return False


def get_vehicles(tokens, device_id):
    """返回 [{sn, name?, ...}]（来自 /vehicle/binding/my-vehicle）"""
    try:
        lst = api.vehicles(tokens, device_id)
    except Exception as e:
        print(f"[!] 获取车辆列表失败：{e}", file=sys.stderr)
        return []
    vehicles = []
    for v in lst if isinstance(lst, list) else []:
        if isinstance(v, dict):
            sn = v.get("wnumber") or v.get("sn") or v.get("serial") or ""
            if sn:
                vehicles.append({"sn": str(sn).strip(),
                                 "name": v.get("vehicle_name") or v.get("name") or ""})
    return vehicles


def month_range(from_ym, to_ym):
    y0, m0 = divmod(from_ym - 1, 100) + (1, 0)  # 简易转换
    # 正确做法：
    y0, m0 = from_ym // 100, from_ym % 100
    y1, m1 = to_ym // 100, to_ym % 100
    months = []
    y, m = y0, m0
    while (y, m) <= (y1, m1):
        months.append(y * 100 + m)
        m += 1
        if m == 13:
            m = 1
            y += 1
    return months


def fetch_month(tokens, device_id, sn, ym, use_cache=True):
    """拉某月行程列表，返回 (rides_list, raw)"""
    cache = CACHE_DIR / f"travel_{sn}_{ym}.json"
    if use_cache and cache.exists():
        raw = cache.read_text(encoding="utf-8")
        try:
            return json.loads(raw), raw
        except Exception:
            pass
    try:
        data = api.travel_list(tokens, device_id, sn, str(ym))
    except Exception as e:
        print(f"    [失败] {sn} {ym}: {e}", file=sys.stderr)
        return None, None
    if data is None:
        return [], ""
    raw = json.dumps(data, ensure_ascii=False)
    cache.write_text(raw, encoding="utf-8")
    return data, raw


def fetch_detail(tokens, device_id, sn, travel_id, use_cache=True):
    cache = CACHE_DIR / f"detail_{sn}_{travel_id}.json"
    if use_cache and cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    try:
        data = api.travel_detail(tokens, device_id, sn, travel_id)
    except Exception as e:
        print(f"    [详情失败] {travel_id}: {e}", file=sys.stderr)
        return None
    cache.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    time.sleep(0.4)  # 温和限速
    return data


def first_key(d, keys):
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return k
    return None


def to_float(v):
    try:
        f = float(v)
        return f if f == f else None  # 排除 NaN
    except (TypeError, ValueError):
        return None


def normalize_ride(item, sn, vehicle_name=""):
    """把一个行程条目归一化；找不到的字段保留 raw 以便后续人工分析"""
    if not isinstance(item, dict):
        return None
    ride = {"sn": sn, "vehicle_name": vehicle_name}
    k = first_key(item, KEY_ID)
    ride["travel_id"] = str(item[k]) if k else None
    k = first_key(item, KEY_START)
    ride["start_time"] = item[k] if k else None
    k = first_key(item, KEY_END)
    ride["end_time"] = item[k] if k else None
    k = first_key(item, KEY_DIST)
    ride["distance_km"] = to_float(item[k]) if k else None
    k = first_key(item, KEY_DUR)
    ride["duration_s"] = to_float(item[k]) if k else None
    k = first_key(item, KEY_USED)
    ride["battery_used_pct"] = to_float(item[k]) if k else None
    k = first_key(item, KEY_MAXSPEED)
    ride["max_speed_kmh"] = to_float(item[k]) if k else None
    ride["avg_speed_kmh"] = None
    if ride["distance_km"] and ride["duration_s"] and ride["duration_s"] > 0:
        ride["avg_speed_kmh"] = round(ride["distance_km"] / (ride["duration_s"] / 3600.0), 2)
    # 详情里若带逐点速度则覆盖计算
    k = first_key(item, KEY_SPEEDS)
    if k and isinstance(item[k], list) and item[k]:
        speeds = [to_float(s) for s in item[k] if to_float(s) is not None]
        if speeds:
            ride["max_speed_kmh"] = round(max(speeds), 2)
            ride["avg_speed_kmh"] = round(sum(speeds) / len(speeds), 2)
            ride["speed_samples"] = speeds
    ride["raw"] = {kk: vv for kk, vv in item.items() if kk not in
                   (set(KEY_ID + KEY_START + KEY_END + KEY_DIST + KEY_DUR + KEY_USED + KEY_MAXSPEED + KEY_SPEEDS))}
    return ride


def enrich_with_detail(tokens, device_id, ride, sn):
    if not ride.get("travel_id"):
        return
    det = fetch_detail(tokens, device_id, sn, ride["travel_id"])
    if not det:
        return
    # 详情可能是 {data: {...}} 包裹
    d = det.get("data") if isinstance(det, dict) and isinstance(det.get("data"), dict) else det
    if not isinstance(d, dict):
        d = det
    ride["detail"] = d
    # 尝试从详情补全/覆盖速度字段
    for key in KEY_MAXSPEED:
        v = d.get(key)
        if to_float(v) is not None:
            ride["max_speed_kmh"] = to_float(v)
            break
    for key in KEY_SPEEDS:
        v = d.get(key)
        if isinstance(v, list) and v:
            speeds = [to_float(s) for s in v if to_float(s) is not None]
            if speeds:
                ride["max_speed_kmh"] = round(max(speeds), 2)
                ride["avg_speed_kmh"] = round(sum(speeds) / len(speeds), 2)
                ride["speed_samples"] = speeds
            break
    # 轨迹点
    for key in KEY_TRACK:
        v = d.get(key)
        if isinstance(v, list) and v:
            ride["track"] = v
            break


def main():
    global CONFIG_DIR
    ap = argparse.ArgumentParser(description="九号出行历史行程抓取器（纯 Python）")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--from", dest="from_ym", type=int, default=202201, help="起始月份 YYYYMM")
    ap.add_argument("--to", dest="to_ym", type=int, default=int(datetime.now().strftime("%Y%m")))
    ap.add_argument("--sn", help="只抓指定车辆 SN")
    ap.add_argument("--no-detail", action="store_true", help="跳过单次行程详情（只抓列表）")
    ap.add_argument("--no-cache", action="store_true", help="不使用缓存")
    args = ap.parse_args()
    CONFIG_DIR = args.config
    CACHE_DIR.mkdir(exist_ok=True)

    if not ensure_login():
        sys.exit(1)

    cfg = api.load_config(CONFIG_DIR)
    tokens = api.load_tokens(CONFIG_DIR)
    device_id = cfg["device_id"]

    vehicles = get_vehicles(tokens, device_id)
    if not vehicles:
        print("[!] 未能获取车辆列表，请用 --sn 指定。", file=sys.stderr)
        print("    python3 fetch_trips.py --sn <车辆SN>", file=sys.stderr)
        sys.exit(1)
    if args.sn:
        vehicles = [v for v in vehicles if v["sn"] == args.sn] or [{"sn": args.sn, "name": args.sn}]
    print(f"[*] 车辆: {[v['sn'] for v in vehicles]}")

    months = month_range(args.from_ym, args.to_ym)
    print(f"[*] 抓取月份: {months[0]} ~ {months[-1]}（共 {len(months)} 个月）")

    all_rides = []
    for v in vehicles:
        sn = v["sn"]
        empty_streak = 0
        for ym in months:
            print(f"[*] {sn} {ym} ...", flush=True)
            data, raw = fetch_month(tokens, device_id, sn, ym, use_cache=not args.no_cache)
            if data is None:
                continue
            if data == [] or (isinstance(data, dict) and not data.get("list")):
                empty_streak += 1
                if empty_streak >= 3 and ym > 202300:
                    print(f"    （连续 {empty_streak} 个月为空，可能已到最早记录，提前结束）")
                    break
                continue
            empty_streak = 0
            lst = data.get("list") if isinstance(data, dict) else data
            if not isinstance(lst, list):
                print(f"    [未知结构] {raw[:200]}", file=sys.stderr)
                continue
            rides = [normalize_ride(it, sn, v.get("name", "")) for it in lst]
            rides = [r for r in rides if r]
            print(f"    -> {len(rides)} 条行程")
            for r in rides:
                if not args.no_detail:
                    enrich_with_detail(tokens, device_id, r, sn)
                all_rides.append(r)

    all_rides.sort(key=lambda r: (r.get("start_time") or ""), reverse=True)
    print(f"\n[+] 共 {len(all_rides)} 条行程")

    # 汇总统计
    with_dist = [r for r in all_rides if r.get("distance_km")]
    with_max = [r for r in all_rides if r.get("max_speed_kmh")]
    stats = {
        "rides": len(all_rides),
        "total_distance_km": round(sum(r.get("distance_km") or 0 for r in with_dist), 2),
        "total_duration_s": round(sum(r.get("duration_s") or 0 for r in all_rides), 1),
        "overall_max_speed_kmh": max((r.get("max_speed_kmh") or 0 for r in with_max), default=None),
        "best_avg_speed_kmh": max((r.get("avg_speed_kmh") or 0 for r in with_dist), default=None),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
    print(f"[+] 总里程 {stats['total_distance_km']} km, 最高速度 {stats['overall_max_speed_kmh']} km/h")

    OUT_JSON.write_text(json.dumps({"stats": stats, "rides": all_rides}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[+] 已写 {OUT_JSON}")

    # CSV（去掉 raw/detail 巨字段）
    if all_rides:
        import csv
        fields = ["start_time", "end_time", "sn", "vehicle_name", "distance_km",
                  "duration_s", "max_speed_kmh", "avg_speed_kmh", "battery_used_pct", "travel_id"]
        with open(OUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in all_rides:
                w.writerow({k: r.get(k) for k in fields})
        print(f"[+] 已写 {OUT_CSV}")


if __name__ == "__main__":
    main()
