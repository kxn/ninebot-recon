#!/usr/bin/env python3
"""ninecli 二进制函数反汇编分析器。
用法: python3 disasm_func.py <start_hex> <end_hex> [--calls]
从 dis.txt 提取函数指令，解析字符串引用与内部调用。
"""
import re, sys, subprocess, json

DIS = "/data/dl/ninebot/dis.txt"
BIN = "/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli"

def build_strmap():
    BASE_OFF, BASE_VA = 0x3ee000, 0x7ee000
    out = subprocess.run(["strings", "-t", "x", "-n", "2", BIN], capture_output=True, text=True).stdout.splitlines()
    strs = []  # (start_va, end_va, text)
    for line in out:
        parts = line.split(None, 1)
        if len(parts) == 2:
            try:
                off = int(parts[0], 16)
            except ValueError:
                continue
            if BASE_OFF <= off < 0x829500:
                text = parts[1]
                start = BASE_VA + (off - BASE_OFF)
                strs.append((start, start + len(text), text))
    def resolve(va):
        for s, e, t in strs:
            if s <= va < e:
                return t
        return None
    return resolve

def load_funcmap():
    """从 gore_out.json 构建 函数名: (start,end) 映射"""
    with open('/data/dl/ninebot/gore_out.json') as f:
        data = json.load(f)
    fmap = {}
    for fn in data.get('UserFunctions', []):
        s, e = fn.get('Start'), fn.get('End')
        if s and e:
            fmap.setdefault(s, []).append(fn.get('FullName',''))
    return fmap

def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    show_calls = '--calls' in sys.argv
    resolve = build_strmap()
    fmap = load_funcmap()

    with open(DIS) as f:
        lines = f.readlines()

    print(f"### 函数 0x{start:x} - 0x{end:x}")
    # 收集该范围的指令行
    in_range = []
    for l in lines:
        m = re.match(r'\s*([0-9a-f]+):', l)
        if m:
            addr = int(m.group(1), 16)
            if start <= addr < end:
                in_range.append(l)
    print(f"({len(in_range)} 条指令)\n")

    for l in in_range:
        # 解析 lea 字符串引用：目标地址在注释 # 0x... 里
        m = re.search(r'lea\s+0x[0-9a-f]+\(%rip\),%(\w+)\s+#\s*0x([0-9a-f]+)', l)
        if m:
            va = int(m.group(2), 16)
            s = resolve(va)
            reg = m.group(1)
            if s:
                print(f"{l.rstrip()}\n      ;; {reg} = {s!r}")
                continue
        # 解析 call
        m = re.search(r'call\s+([0-9a-f]+)', l)
        if m:
            target = int(m.group(1), 16)
            names = fmap.get(target, [])
            if names:
                print(f"{l.rstrip()}  ;; -> {names[0]}")
            elif show_calls:
                print(f"{l.rstrip()}  ;; -> 0x{target:x} (非业务函数)")
            continue
        print(l.rstrip())

if __name__ == "__main__":
    main()
