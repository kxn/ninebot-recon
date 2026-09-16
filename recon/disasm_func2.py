#!/usr/bin/env python3
"""ninecli 二进制函数反汇编分析器 v2。
用法: python3 disasm_func2.py <start_hex> <end_hex>
- 解析 lea+mov 配对，精确切出字符串（Go 字符串 = 地址 + 长度）
- 解析 call 目标为函数名
"""
import re, sys, subprocess, json, struct

DIS = "/data/dl/ninebot/dis.txt"
BIN = "/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli"

def load_raw_strings():
    """读取 .rodata 原始字节，返回 va->bytes 映射（按段映射）"""
    # LOAD 2: 文件 0x3ee000-0x829000 -> VA 0x7ee000-0xc29000
    with open(BIN, 'rb') as f:
        f.seek(0x3ee000)
        data = f.read(0x829000 - 0x3ee000)
    base_va = 0x7ee000
    return base_va, data

def load_funcmap():
    with open('/data/dl/ninebot/gore_out.json') as f:
        data = json.load(f)
    fmap = {}
    for fn in data.get('UserFunctions', []) + data.get('StdFunctions', []):
        s, e = fn.get('Start'), fn.get('End')
        if s and e:
            fmap.setdefault(s, []).append(fn.get('FullName',''))
    return fmap

def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    base_va, raw = load_raw_strings()
    fmap = load_funcmap()

    with open(DIS) as f:
        lines = f.readlines()

    # 提取范围内的指令行 (addr -> 行)
    instrs = []
    for l in lines:
        m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s+(\S.*)', l)
        if m:
            addr = int(m.group(1), 16)
            if start <= addr < end:
                instrs.append((addr, l))
    instrs.sort()

    def read_cstr(va, length):
        """从 .rodata 读 va 处 length 字节"""
        off = va - base_va
        if off < 0 or off + length > len(raw):
            return None
        chunk = raw[off:off+length]
        # 取到第一个不可打印字符为止
        s = chunk.decode('utf-8', 'replace')
        return s

    print(f"### 函数 0x{start:x} - 0x{end:x} ({len(instrs)} 条指令)")
    i = 0
    while i < len(instrs):
        addr, l = instrs[i]
        # call 引用（先解析，便于回溯参数）
        m = re.search(r'call\s+0x([0-9a-f]+)', l)
        if m:
            target = int(m.group(1), 16)
            names = fmap.get(target, [])
            name = names[0] if names else f"0x{target:x}"
            # mapassign_faststr: rdi=map, rsi=key_ptr, rdx=key_len
            if 'mapassign_faststr' in name:
                # 回溯 15 条指令找 rsi 的 lea 和 rdx 的 mov
                key = None
                for j in range(i-1, max(0, i-15), -1):
                    a2, l2 = instrs[j]
                    m2 = re.search(r'lea\s+0x[0-9a-f]+\(%rip\),%rsi\s+#\s*0x([0-9a-f]+)', l2)
                    if m2:
                        va = int(m2.group(1), 16)
                        # 找 rdx 长度
                        for k in range(j+1, i):
                            a3, l3 = instrs[k]
                            m3 = re.search(r'mov\s+\$0x([0-9a-f]+),%rdx', l3)
                            if m3:
                                length = int(m3.group(1), 16)
                                s = read_cstr(va, length)
                                key = s if s is not None else f"0x{va:x}(len={length})"
                                break
                        if key:
                            break
                print(f"0x{addr:x}: MAPSET key={key!r}")
            else:
                print(f"0x{addr:x}: CALL {name}")
            i += 1
            continue
        # lea 字符串引用
        m = re.search(r'lea\s+0x[0-9a-f]+\(%rip\),%(\w+)\s+#\s*0x([0-9a-f]+)', l)
        if m:
            va = int(m.group(2), 16)
            reg = m.group(1)
            # 找后续的 mov $imm,%reg（同一寄存器，10 条内）
            length = None
            for j in range(i+1, min(i+10, len(instrs))):
                a2, l2 = instrs[j]
                m2 = re.search(r'mov\s+\$0x([0-9a-f]+),%' + reg + r'\b', l2)
                if m2:
                    length = int(m2.group(1), 16)
                    break
                if re.search(r'call|ret|jmp', l2):
                    break
            if length is not None:
                s = read_cstr(va, length)
                if s is not None and s.strip():
                    print(f"0x{addr:x}: STR {s!r}")
                    i += 1
                    continue
        # 立即数（常量）提示
        m = re.search(r'mov\s+\$0x([0-9a-f]+),%\w+', l)
        if m:
            val = int(m.group(1), 16)
            print(f"0x{addr:x}: CONST 0x{val:x} ({val})")
            i += 1
            continue
        i += 1

if __name__ == "__main__":
    main()
