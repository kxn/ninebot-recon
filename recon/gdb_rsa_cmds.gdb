set pagination off
set confirm off
set breakpoint pending on

break *0x5cc120
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
regs = {n: r(n) for n in ('rax','rbx','rcx','rdi','rsi','r8','r9','r10')}
print("RSA_REGS", {k: hex(v) for k, v in regs.items()})
for n, p in regs.items():
    if p and p < 0x7fffffffffff:
        try:
            data = inf.read_memory(p, 64).tobytes()
            print("RSA_MEM", n, hex(p), data[:48].hex(), repr(data[:48]))
        except Exception:
            pass
  end
  continue
end
run
