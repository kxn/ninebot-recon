set pagination off
set confirm off
set breakpoint pending on

# 0x6ca1e5: 0x47eb1a 调用前 —— 检查 0x190/0x1a0 是否已填 P/T
break *0x6ca1e5
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
raw = bytes(inf.read_memory(r('rsp') + 0x190, 0x20).tobytes())
print("=== @0x6ca1e5 P/T slots (0x190-0x1a8):", raw.hex())
  end
  continue
end

# 0x6ca213: 组装开始前
break *0x6ca213
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
raw = bytes(inf.read_memory(r('rsp') + 0x160, 0x50).tobytes())
import struct
vals = []
for i in range(5):
    ptr = struct.unpack_from('<Q', raw, i*16)[0]
    ln = struct.unpack_from('<Q', raw, i*16+8)[0]
    s = bytes(inf.read_memory(ptr, ln)).decode('utf-8','replace') if ptr and 0 < ln < 2000 else f"<nil {ln}>"
    vals.append(s)
print("=== @0x6ca213 struct:", {n: v[:40] for n, v in zip('DHKPT', vals)})
  end
  continue
end

# 0x6cace5: ComputeCheckcode 的 0x4f3dc0 调用前 —— 看 hex 是否小写
break *0x6cace5
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
print("=== @0x6cace5 (before ToUpper): rax=0x%x rbx=%d" % (r('rax'), r('rbx')))
try:
    s = bytes(inf.read_memory(r('rax'), r('rbx')).tobytes())
    print("    hex =", s.decode())
except Exception as e:
    print("    ERR", e)
  end
  continue
end

run
