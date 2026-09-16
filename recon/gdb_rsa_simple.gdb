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
try:
    msg = inf.read_memory(r('rdi'), r('rsi')).tobytes()
    open('/tmp/rsa_msg.bin','wb').write(msg)
    pk = r('rcx')
    nat_ptr = int.from_bytes(inf.read_memory(pk+8, 8).tobytes(), 'little')
    nat_len = int.from_bytes(inf.read_memory(pk+16, 8).tobytes(), 'little')
    limbs = inf.read_memory(nat_ptr, nat_len*8).tobytes()
    nb = int.from_bytes(limbs, 'little').to_bytes(128, 'big')
    open('/tmp/rsa_n1.bin','wb').write(nb)
    print("RSA_MSG %d %r" % (r('rsi'), msg))
    print("RSA_N1 %s..%s" % (nb.hex()[:16], nb.hex()[-16:]))
except Exception as e:
    print("RSA_ERR", e)
  continue
end
run
