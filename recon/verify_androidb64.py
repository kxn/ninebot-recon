#!/usr/bin/env python3
"""unicorn 动态执行 AndroidB64，确认输出格式（76 字符换行？尾部换行？）。"""
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UcError
from unicorn.x86_const import *
import base64, struct

BIN_DATA = open('/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli','rb').read()
FN_START, FN_END = 0x6c95a0, 0x6c9840
B64_CALL = 0x6c95d5     # call 0x4edce0 (base64 encode)
B64_RET = 0x6c95da
GROW_CALL = 0x6c96d6    # call 0x478940 (growslice)
GROW_RET = 0x6c96db
MEM = 0x80000000        # 预留工作内存

def run(data_in: bytes) -> bytes:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # 映射 .text / .rodata / .data（0x401000-0xc88000 文件镜像）
    uc.mem_map(0x401000, 0x8ab000)
    uc.mem_write(0x401000, BIN_DATA[0x1000:0x1000 + (0xc88000 - 0x401000)])
    # 工作内存
    uc.mem_map(MEM, 0x100000)
    # 栈
    STACK = 0x70000000
    uc.mem_map(STACK, 0x10000)
    rsp = STACK + 0x8000
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.mem_write(rsp, struct.pack('<Q', 0x401000))  # 返回地址
    # g 结构
    G = 0x6fff0000
    uc.mem_map(G, 0x1000)
    uc.mem_write(G + 0x10, b'\x00' * 8)
    uc.reg_write(UC_X86_REG_R14, G)
    # 输入
    in_ptr = MEM + 0x1000
    uc.mem_write(in_ptr, data_in)
    uc.reg_write(UC_X86_REG_RAX, in_ptr)
    uc.reg_write(UC_X86_REG_RBX, len(data_in))
    uc.reg_write(UC_X86_REG_RCX, len(data_in))

    # 预留缓冲区分配器
    heap = [MEM + 0x2000]

    def hook_b64(uc, address, size, user_data):
        # 从 rbx/rcx 读输入，标准 base64 编码
        src = bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RBX), uc.reg_read(UC_X86_REG_RCX)))
        out = base64.b64encode(src)
        ptr = heap[0]; heap[0] += (len(out) + 0xf) & ~0xf
        uc.mem_write(ptr, out)
        uc.reg_write(UC_X86_REG_RAX, ptr)
        uc.reg_write(UC_X86_REG_RBX, len(out))
        uc.reg_write(UC_X86_REG_RIP, B64_RET)

    def hook_grow(uc, address, size, user_data):
        # growslice(old_ptr=rbx, old_len=rcx, old_cap=rdi, newcap=rsi) -> (rax=ptr, rbx=len, rcx=cap)
        new_len = uc.reg_read(UC_X86_REG_RBX)   # 入参 rbx = 目标长度
        ptr = heap[0]; heap[0] += 0x1000
        uc.reg_write(UC_X86_REG_RAX, ptr)
        uc.reg_write(UC_X86_REG_RBX, new_len)
        uc.reg_write(UC_X86_REG_RCX, 0x1000)
        uc.reg_write(UC_X86_REG_RIP, GROW_RET)

    uc.hook_add(UC_HOOK_CODE, hook_b64, begin=B64_CALL, end=B64_CALL)
    uc.hook_add(UC_HOOK_CODE, hook_grow, begin=GROW_CALL, end=GROW_CALL)
    try:
        uc.emu_start(FN_START, 0x401000)  # ret 后跳 0x401000 停止
        # 返回值 rax/rbx = 输出 ptr/len
        out_ptr = uc.reg_read(UC_X86_REG_RAX)
        out_len = uc.reg_read(UC_X86_REG_RBX)
        return bytes(uc.mem_read(out_ptr, out_len))
    except UcError as e:
        return b'ERR:' + str(e).encode() + b' rip=' + hex(uc.reg_read(UC_X86_REG_RIP)).encode()

if __name__ == '__main__':
    tests = [b'', b'a', b'hello', b'x' * 56, b'x' * 57, b'x' * 58, b'x' * 113, b'x' * 114, b'x' * 115]
    for t in tests:
        out = run(t)
        print(f"in={len(t):3d}  out({len(out):3d}): {out!r}")
