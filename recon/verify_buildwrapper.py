#!/usr/bin/env python3
"""unicorn 执行二进制 BuildWrapper，与 Python 实现逐字节对比。"""
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UcError
from unicorn.x86_const import *
import base64, struct, sys
sys.path.insert(0, '/data/dl/ninebot')
from ninebot_crypto import build_wrapper

BIN_DATA = open('/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli','rb').read()
FN_START, FN_END = 0x6cc4c0, 0x6cc7a0
B64_CALL, B64_RET = 0x6c95d5, 0x6c95da       # AndroidB64 内 base64
GROW_CALL, GROW_RET = 0x6c96d6, 0x6c96db     # AndroidB64 内 growslice
MEM = 0x80000000

def run_buildwrapper(data: bytes, kd: dict, platform: int, ts: int) -> bytes:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x401000, 0x8ab000)
    uc.mem_write(0x401000, BIN_DATA[0x1000:0x1000 + (0xc88000 - 0x401000)])
    uc.mem_map(MEM, 0x100000)
    STACK = 0x70000000
    uc.mem_map(STACK, 0x10000)
    rsp = STACK + 0x8000
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.mem_write(rsp, struct.pack('<Q', 0x401000))
    G = 0x6fff0000
    uc.mem_map(G, 0x1000)
    uc.mem_write(G + 0x10, b'\x00' * 8)
    uc.reg_write(UC_X86_REG_R14, G)

    # 数据区：输入 data + 4 个 kd 字符串
    heap = [MEM + 0x1000]
    def alloc(sz):
        p = heap[0]; heap[0] += (sz + 0xf) & ~0xf; return p
    dptr = alloc(len(data)); uc.mem_write(dptr, data)
    kd_ptrs = {}
    for name in ('kd1', 'kd2', 'kd3', 'kd4'):
        s = kd[name].encode()
        p = alloc(len(s)); uc.mem_write(p, s)
        kd_ptrs[name] = (p, len(s))

    # 参数（Go ABI）：rax=data_ptr rbx=data_len rcx=platform rdi=timestamp
    # 栈参数（入口 rsp+8..）：kd1,kd2,kd3,kd4 各 (ptr,len) 8 qword
    uc.reg_write(UC_X86_REG_RAX, dptr)
    uc.reg_write(UC_X86_REG_RBX, len(data))
    uc.reg_write(UC_X86_REG_RCX, platform)
    uc.reg_write(UC_X86_REG_RDI, ts)
    off = rsp + 8
    for name in ('kd1', 'kd2', 'kd3', 'kd4'):
        p, ln = kd_ptrs[name]
        uc.mem_write(off, struct.pack('<QQ', p, ln)); off += 16

    # hook：AndroidB64 的 base64 和 growslice
    def hook_b64(uc, address, size, user_data):
        src = bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RBX), uc.reg_read(UC_X86_REG_RCX)))
        out = base64.b64encode(src)
        p = heap[0]; heap[0] += (len(out) + 0xf) & ~0xf
        uc.mem_write(p, out)
        uc.reg_write(UC_X86_REG_RAX, p)
        uc.reg_write(UC_X86_REG_RBX, len(out))
        uc.reg_write(UC_X86_REG_RIP, B64_RET)

    def hook_grow(uc, address, size, user_data):
        new_len = uc.reg_read(UC_X86_REG_RBX)
        p = heap[0]; heap[0] += 0x1000
        uc.reg_write(UC_X86_REG_RAX, p)
        uc.reg_write(UC_X86_REG_RBX, new_len)
        uc.reg_write(UC_X86_REG_RCX, 0x1000)
        uc.reg_write(UC_X86_REG_RIP, GROW_RET)

    uc.hook_add(UC_HOOK_CODE, hook_b64, begin=B64_CALL, end=B64_CALL)
    uc.hook_add(UC_HOOK_CODE, hook_grow, begin=GROW_CALL, end=GROW_CALL)
    try:
        uc.emu_start(FN_START, 0x401000)
        p = uc.reg_read(UC_X86_REG_RAX)
        ln = uc.reg_read(UC_X86_REG_RBX)
        return bytes(uc.mem_read(p, ln))
    except UcError as e:
        return b'ERR:' + str(e).encode() + b'@' + hex(uc.reg_read(UC_X86_REG_RIP)).encode()

if __name__ == '__main__':
    kd = {"kd1": "aaaaaaaaaaa", "kd2": "bbbbbbbbbb", "kd3": "cccccccccc", "kd4": "dddddddd"}
    data = b'{"sn":"NB12345","month":"202608"}'
    ts = 1786000000000
    bin_out = run_buildwrapper(data, kd, 10, ts)
    py_out = build_wrapper(data, kd["kd1"], kd["kd2"], kd["kd3"], kd["kd4"], 10, ts).encode()
    print("bin:", bin_out[:200])
    print("py :", py_out[:200])
    if bin_out.startswith(b'ERR'):
        print("UNICORN 失败:", bin_out)
    elif bin_out == py_out:
        print("✅ 字节级完全一致", len(bin_out), "bytes")
    else:
        print("❌ 不一致")
        for i, (a, b) in enumerate(zip(bin_out, py_out)):
            if a != b:
                print(f"  首个差异 @{i}: bin={bin_out[max(0,i-20):i+20]!r}")
                print(f"               py ={py_out[max(0,i-20):i+20]!r}")
                break
