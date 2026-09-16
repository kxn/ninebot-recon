#!/usr/bin/env python3
"""用 unicorn 动态执行 ninecli 二进制中的 crypto.DeriveKey，验证纯 Python 公式实现。

DeriveKey(A,B,C,D []byte) [16]byte  @ VA 0x6c99e0-0x6c9b80
Go ABI: rax=A_ptr rbx=A_len rcx=B_ptr rdi=B_len rsi=C_ptr r8=C_len r9=D_ptr r10=D_len
唯一外部调用 0x478860（堆分配 16 字节）→ hook 返回预留缓冲区。
"""
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *
import random, sys

BIN = '/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli'
BIN_DATA = open(BIN, 'rb').read()

DERIVE_START, DERIVE_END = 0x6c99e0, 0x6c9b80
ALLOC_CALL_ADDR = 0x6c9ae3   # call 0x478860
ALLOC_RET_ADDR = 0x6c9ae8
OUTBUF = 0x7ffff000          # 预留输出缓冲区（16 字节对齐）

def rol32(v, n):
    n %= 32
    return ((v << n) | (v >> (32 - n))) & 0xffffffff

def rol8acc(s: bytes) -> int:
    v = 0
    for b in s:
        v = rol32(v, 8) ^ b
    return v & 0xffffffff

def derivekey_py(a: bytes, b: bytes, c: bytes, d: bytes) -> bytes:
    """从反汇编推导的公式"""
    A = rol8acc(a); B = rol8acc(b); C = rol8acc(c); D = rol8acc(d)
    x = A ^ C
    y = B ^ D
    fx = rol32(x, 8) ^ x ^ rol32(x, 24)
    gy = rol32(y, 8) ^ y ^ rol32(y, 24)
    a1 = A ^ gy
    b1 = B ^ fx
    c1 = C ^ gy
    d1 = D ^ fx
    out3 = (c1 & b1) ^ a1
    tmp = (~(c1 ^ d1 ^ ((c1 | d1) ^ b1))) & 0xffffffff
    out2 = out3 ^ tmp
    out1 = ((tmp | out3) ^ ((c1 | d1) ^ b1)) & 0xffffffff
    out0 = ((~((c1 | d1) ^ b1) & out2) ^ d1) & 0xffffffff
    import struct
    return struct.pack('<IIII', out0, out1, out2, out3)

def derivekey_bin(a: bytes, b: bytes, c: bytes, d: bytes) -> bytes:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # 映射代码段（0x401000-0x829000 覆盖 DeriveKey 所在 .text/.rodata）
    CODE_VA, CODE_OFF, CODE_SZ = 0x401000, 0x1000, 0x829000 - 0x401000
    uc.mem_map(CODE_VA, CODE_SZ)
    uc.mem_write(CODE_VA, BIN_DATA[CODE_OFF:CODE_OFF + CODE_SZ])
    # 映射栈
    STACK = 0x10000000
    uc.mem_map(STACK, 0x10000)
    uc.reg_write(UC_X86_REG_RSP, STACK + 0x8000)
    # 映射输入区 + 输出缓冲区（0x7fff0000-0x80010000）
    uc.mem_map(0x7fff0000, 0x20000)
    # 输入字符串
    inputs = {}
    cur = 0x7fff8000
    for name, s in (('A', a), ('B', b), ('C', c), ('D', d)):
        inputs[name] = cur
        uc.mem_write(cur, s)
        cur += (len(s) + 15) & ~15
    # g 结构（stackguard0 = 0）
    G = 0x6fff0000
    uc.mem_map(G, 0x1000)
    uc.mem_write(G + 0x10, b'\x00\x00\x00\x00\x00\x00\x00\x00')
    # 参数（Go 内部 ABI：slice = ptr,len,cap 三个寄存器位；前 3 个 slice 走寄存器，第 4 个走栈）
    # A: rax/rbx  B: rdi/rsi  C: r9/r10  D: 栈参数 [入口rsp+8]/[+16]/[+24]
    uc.reg_write(UC_X86_REG_RAX, inputs['A']); uc.reg_write(UC_X86_REG_RBX, len(a))
    uc.reg_write(UC_X86_REG_RDI, inputs['B']); uc.reg_write(UC_X86_REG_RSI, len(b))
    uc.reg_write(UC_X86_REG_R9,  inputs['C']); uc.reg_write(UC_X86_REG_R10, len(c))
    entry_rsp = uc.reg_read(UC_X86_REG_RSP)
    import struct as _s
    uc.mem_write(entry_rsp + 8,  _s.pack('<Q', inputs['D']))
    uc.mem_write(entry_rsp + 16, _s.pack('<Q', len(d)))
    uc.mem_write(entry_rsp + 24, _s.pack('<Q', len(d)))
    uc.reg_write(UC_X86_REG_R14, G)
    # 栈上的返回地址（ret 后跳到 0x401000，emu 在此停止）
    uc.mem_write(entry_rsp, _s.pack('<Q', 0x401000))
    # hook 堆分配调用
    def hook_alloc(uc, address, size, user_data):
        uc.reg_write(UC_X86_REG_RAX, OUTBUF)
        uc.reg_write(UC_X86_REG_RIP, ALLOC_RET_ADDR)
    uc.hook_add(UC_HOOK_CODE, hook_alloc, begin=ALLOC_CALL_ADDR, end=ALLOC_CALL_ADDR)
    # 执行（until=0x401000：执行到返回地址处停止）
    uc.emu_start(DERIVE_START, 0x401000)
    rax = uc.reg_read(UC_X86_REG_RAX)
    return bytes(uc.mem_read(rax, 16))

def main():
    cases = [
        (b'abcdefghijklm', b'0123456789ab', b'XYZ', b'ninebot!'),
        (b'a', b'b', b'c', b'd'),
        (b'', b'', b'', b''),
        (b'keydataone', b'keydatatwo', b'keydatathree', b'keydatafour'),
        (bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96)), bytes(range(96, 128))),
    ]
    random.seed(42)
    for _ in range(6):
        cases.append((bytes(random.randbytes(random.randint(1, 40))),
                      bytes(random.randbytes(random.randint(1, 40))),
                      bytes(random.randbytes(random.randint(1, 40))),
                      bytes(random.randbytes(random.randint(1, 40)))))
    ok = True
    for a, b, c, d in cases:
        py = derivekey_py(a, b, c, d)
        bi = derivekey_bin(a, b, c, d)
        match = py == bi
        ok &= match
        print(f"{'PASS' if match else 'FAIL'}  A={a!r:.40} B={b!r:.40}")
        if not match:
            print(f"  py: {py.hex()}")
            print(f"  bin:{bi.hex()}")
    print('ALL PASS' if ok else 'MISMATCH!')

if __name__ == '__main__':
    main()
