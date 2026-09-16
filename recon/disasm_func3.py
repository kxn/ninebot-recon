#!/usr/bin/env python3
"""精确字符串解析版反汇编分析器。

用法: python3 disasm_func3.py <start_hex> <end_hex> [--calls] [--raw]
从 dis.txt 提取函数指令；lea 引用按 VA 直接从二进制读精确字符串（非 strings 合并串）。
"""
import re, sys, json, subprocess

DIS = "/data/dl/ninebot/dis.txt"
BIN = "/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli"

# .rodata: VA 0x7ee000 起, size 0x1b7c19 (readelf), file offset 0x3ee000
RO_VA, RO_OFF = 0x7ee000, 0x3ee000
RO_END = 0x9a5c50

BIN_DATA = open(BIN, 'rb').read()

def str_at_va(va: int, maxlen=160) -> str | None:
    """从二进制读取 VA 处的字符串（到 NUL 或非法 UTF-8 为止）"""
    if not (RO_VA <= va < RO_END):
        return None
    off = RO_OFF + (va - RO_VA)
    chunk = BIN_DATA[off:off + maxlen]
    out = []
    for b in chunk:
        if b == 0:
            break
        out.append(b)
    try:
        s = bytes(out).decode('utf-8')
    except UnicodeDecodeError:
        # 允许单字节替换，截到首个非法处
        s = bytes(out).decode('utf-8', 'ignore')
    return s

def load_funcmap():
    with open('/data/dl/ninebot/gore_out.json') as f:
        data = json.load(f)
    fmap = {}
    for fn in data.get('UserFunctions', []):
        s, e = fn.get('Start'), fn.get('End')
        if s and e:
            fmap.setdefault(s, []).append(fn.get('FullName', ''))
    return fmap

def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    show_calls = '--calls' in sys.argv
    raw = '--raw' in sys.argv
    fmap = load_funcmap()
    with open(DIS) as f:
        lines = f.readlines()
    print(f"### 函数 0x{start:x} - 0x{end:x}")
    in_range = []
    for l in lines:
        m = re.match(r'\s*([0-9a-f]+):', l)
        if m:
            addr = int(m.group(1), 16)
            if start <= addr < end:
                in_range.append(l)
    print(f"({len(in_range)} 条指令)\n")
    for l in in_range:
        note = ""
        m = re.search(r'lea\s+0x[0-9a-f]+\(%rip\),%(\w+)\s+#\s*0x([0-9a-f]+)', l)
        if m:
            va = int(m.group(2), 16)
            s = str_at_va(va)
            reg = m.group(1)
            if s:
                note = f"      ;; {reg} = {s!r}"
        m = re.search(r'call\s+([0-9a-f]+)', l)
        if m:
            target = int(m.group(1), 16)
            names = fmap.get(target, [])
            if names:
                note += f"  ;; -> {names[0]}"
            elif show_calls:
                note += f"  ;; -> 0x{target:x} (非业务函数)"
        print(l.rstrip() + note)

if __name__ == "__main__":
    main()
