#!/usr/bin/env python3
"""精确字符串解析版 v2：lea VA + 后续 mov $len 配对，精确切片 Go rodata 字符串。

用法: python3 disasm_func4.py <start_hex> <end_hex>
"""
import re, sys, json

DIS = "/data/dl/ninebot/dis.txt"
BIN = "/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli"
RO_VA, RO_OFF = 0x7ee000, 0x3ee000
RO_END = 0x9a5c50
BIN_DATA = open(BIN, 'rb').read()

def read_at(va: int, n: int) -> str:
    if not (RO_VA <= va < RO_END):
        return f"<non-rodata 0x{va:x}>"
    off = RO_OFF + (va - RO_VA)
    raw = BIN_DATA[off:off + n]
    return raw.decode('utf-8', 'replace')

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
    fmap = load_funcmap()
    with open(DIS) as f:
        lines = f.readlines()
    ins = []  # (addr, text)
    for l in lines:
        m = re.match(r'\s*([0-9a-f]+):\s*(.*)', l)
        if m:
            addr = int(m.group(1), 16)
            if start <= addr < end:
                ins.append((addr, m.group(2).strip()))
    print(f"### 函数 0x{start:x} - 0x{end:x} ({len(ins)} 条指令)")

    # 第一遍: 收集 lea -> (addr_idx, reg, va)
    leas = []  # (idx, reg, va)
    for i, (addr, text) in enumerate(ins):
        m = re.search(r'lea\s+0x([0-9a-f]+)\(%rip\),%(\w+)\s+#\s*0x([0-9a-f]+)', text)
        if m:
            va = int(m.group(3), 16)
            if RO_VA <= va < RO_END:
                leas.append((i, m.group(2), va))
    # 对每个 lea，向后找 mov $imm 形式（任意寄存器或 rsp 槽位，限 7 条内）
    for idx, reg, va in leas:
        found = None
        for j in range(idx + 1, min(idx + 7, len(ins))):
            m = re.search(r'movq?\s+\$0x([0-9a-f]+),%(\w+)', ins[j][1])
            if m:
                found = (int(m.group(1), 16), m.group(2))
                break
            m2 = re.search(r'movq?\s+\$0x([0-9a-f]+),0x[0-9a-f]+\(%rsp\)', ins[j][1])
            if m2:
                found = (int(m2.group(1), 16), 'rsp')
                break
        if found:
            n, lreg = found
            print(f"  @{ins[idx][0]:#x} lea {reg} -> VA 0x{va:x} len={n} [{lreg}] = {read_at(va, n)!r}")
        else:
            print(f"  @{ins[idx][0]:#x} lea {reg} -> VA 0x{va:x} (未找到长度)")

    # 内部调用
    for addr, text in ins:
        m = re.search(r'call\s+([0-9a-f]+)', text)
        if m:
            target = int(m.group(1), 16)
            names = fmap.get(target, [])
            if names:
                print(f"  @{addr:#x} call {names[0]}")

if __name__ == "__main__":
    main()
