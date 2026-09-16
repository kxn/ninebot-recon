#!/usr/bin/env python3
"""批量反汇编 crypto/api 包函数，带 rodata 字符串引用解析，输出到 dump_crypto.txt。

用法: python3 dump_crypto_funcs.py
"""
import re, json

DIS = "/data/dl/ninebot/dis.txt"
BIN = "/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli"
OUT = "/data/dl/ninebot/dump_crypto.txt"

# (start, end, label)
FUNCS = [
    (0x6c95a0, 0x6c9840, "crypto.AndroidB64"),
    (0x6c9840, 0x6c99e0, "crypto.BuildControlCmd"),
    (0x6c99e0, 0x6c9b80, "crypto.DeriveKey"),
    (0x6c9b80, 0x6ca000, "crypto.init.0 (RSA key)"),
    (0x6ca000, 0x6ca300, "crypto.EncryptRequest"),
    (0x6ca300, 0x6ca880, "crypto.DecryptResponse"),
    (0x6ca880, 0x6ca9e0, "crypto.GenKReq"),
    (0x6ca9e0, 0x6cab20, "crypto.GenNonce"),
    (0x6cab20, 0x6cac40, "crypto.GenKeyData"),
    (0x6cac40, 0x6cad40, "crypto.ComputeCheckcode"),
    (0x6cad40, 0x6caea0, "crypto.randHex"),
    (0x6caea0, 0x6cb020, "crypto.randFromCharset"),
    (0x6cb020, 0x6cb340, "crypto.unescapeJSONString"),
    (0x6cb340, 0x6cbda0, "crypto.PassportCanonicalString"),
    (0x6cbda0, 0x6cbf00, "crypto.PassportSign"),
    (0x6cbf00, 0x6cc0a0, "crypto.EncodeOrderedJSON"),
    (0x6cc0a0, 0x6cc4c0, "crypto.writeJSONValue"),
    (0x6cc4c0, 0x6cc7a0, "crypto.BuildWrapper"),
    (0x6cc7a0, 0x6cc960, "crypto.jsonEscapeString"),
    (0x6cc960, 0x6ccac0, "crypto.PKCS7Unpad"),
    (0x6ccac0, 0x6ccce0, "crypto.AESEncrypt"),
    (0x6ccce0, 0x6ccec0, "crypto.AESDecrypt"),
    (0x6cea80, 0x6ceb60, "api.stringFieldMap"),
    (0x6ceb60, 0x6cece0, "api.randomHex"),
    (0x6cece0, 0x6cf0e0, "api.BuildInner"),
]

def load_funcmap():
    with open('/data/dl/ninebot/gore_out.json') as f:
        data = json.load(f)
    fmap = {}
    for fn in data.get('UserFunctions', []):
        s, e = fn.get('Start'), fn.get('End')
        if s and e:
            fmap.setdefault(s, []).append(fn.get('FullName', ''))
    return fmap

def build_strmap():
    import subprocess
    BASE_OFF, BASE_VA = 0x3ee000, 0x7ee000
    out = subprocess.run(["strings", "-t", "x", "-n", "2", BIN],
                         capture_output=True, text=True).stdout.splitlines()
    strs = []
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

def main():
    fmap = load_funcmap()
    resolve = build_strmap()

    with open(DIS) as f:
        lines = f.readlines()
    ins = []  # (addr, text)
    for l in lines:
        m = re.match(r'\s*([0-9a-f]+):\s*(.*)', l)
        if m:
            ins.append((int(m.group(1), 16), m.group(2).strip()))

    out_lines = []
    for start, end, label in FUNCS:
        body = [(a, t) for a, t in ins if start <= a < end]
        out_lines.append(f"\n{'='*100}\n### {label}  0x{start:x}-0x{end:x}  ({len(body)} ins)\n{'='*100}")
        for addr, text in body:
            annotated = text
            m = re.search(r'lea\s+0x[0-9a-f]+\(%rip\),%(\w+)\s+#\s*0x([0-9a-f]+)', text)
            if m:
                va = int(m.group(2), 16)
                s = resolve(va)
                if s:
                    annotated += f"   ;; {m.group(1)} = {s!r}"
            m = re.search(r'call\s+([0-9a-f]+)', text)
            if m:
                target = int(m.group(1), 16)
                names = fmap.get(target, [])
                if names:
                    annotated += f"   ;; -> {names[0]}"
            out_lines.append(f"  0x{addr:x}:\t{annotated}")

    with open(OUT, 'w') as f:
        f.write("\n".join(out_lines))
    print(f"written {OUT}, {len(out_lines)} lines")

if __name__ == "__main__":
    main()
