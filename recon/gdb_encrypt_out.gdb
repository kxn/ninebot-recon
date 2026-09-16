set pagination off
set confirm off
set breakpoint pending on

# 0x6ca1e0 call 0x4edce0 之后 = b64(RSA) 返回 → rax/rbx = K
break *0x6ca1e5
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
print("=== after b64(RSA) @0x6ca1e5: rax=0x%x rbx=%d (K ptr/len)" % (r('rax'), r('rbx')))
if 0 < r('rbx') < 1000:
    try:
        k = bytes(inf.read_memory(r('rax'), r('rbx')).tobytes())
        print("    K =", k[:80])
    except Exception as e:
        print("    K_ERR", e)
  end
  continue
end

# 0x6ca250: K.ptr 写入前 —— 验证 rax 是否仍为 b64 结果（0x47eb1a 是否破坏）
break *0x6ca250
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
print("=== @0x6ca250 (before K store): rax=0x%x rbx=%d" % (r('rax'), r('rbx')))
  end
  continue
end

# 0x6ca268 ret: dump 返回结构体（0x160(%rsp) 起 0x50 字节 = D/H/K/P/T）
break *0x6ca260
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
print("=== EncryptRequest return struct @rsp+0x160 ===")
try:
    raw = bytes(inf.read_memory(r('rsp') + 0x160, 0x50).tobytes())
    import struct
    fields = []
    for i in range(5):
        ptr = struct.unpack_from('<Q', raw, i*16)[0]
        ln = struct.unpack_from('<Q', raw, i*16+8)[0]
        s = bytes(inf.read_memory(ptr, ln)).decode('utf-8','replace') if ptr and 0 < ln < 2000 else f"<nil {ln}>"
        fields.append(s)
    names = ['D','H','K','P','T']
    for n_, v in zip(names, fields):
        print(f"    {n_} = {v[:100]!r}{'...' if len(v)>100 else ''}")
except Exception as e:
    print("    DUMP_ERR", e)
  end
  continue
end

run
