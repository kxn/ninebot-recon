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
pk = r('rcx')
def dump_n(label, nptr):
    try:
        nat_ptr = int.from_bytes(inf.read_memory(nptr+8, 8).tobytes(), 'little')
        nat_len = int.from_bytes(inf.read_memory(nptr+16, 8).tobytes(), 'little')
        limbs = inf.read_memory(nat_ptr, nat_len*8).tobytes()
        n_int = int.from_bytes(limbs, 'little')
        nb = n_int.to_bytes((n_int.bit_length()+7)//8, 'big')
        print("N_%s: %s" % (label, nb.hex()))
        open('/tmp/rsa_n_%s.bin' % label, 'wb').write(nb)
    except Exception as e:
        print("N_%s ERR %s" % (label, e))
print("PK_MEM:", inf.read_memory(pk, 64).tobytes().hex())
dump_n("1", int.from_bytes(inf.read_memory(pk, 8).tobytes(), 'little'))
dump_n("2", int.from_bytes(inf.read_memory(pk+16, 8).tobytes(), 'little'))
  end
  continue
end
run
