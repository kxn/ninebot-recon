set pagination off
set confirm off
set breakpoint pending on

break *0x6cac40
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if 0 < r('rbx') < 500:
    try:
        open('/tmp/cc_input.bin','wb').write(inf.read_memory(r('rax'), r('rbx')).tobytes())
    except Exception as e:
        print("CC_ERR", e)
  end
  continue
end

break *0x5d1780
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if 500 <= r('rbx') < 20000:
    try:
        open('/tmp/wrapper_md5.bin','wb').write(inf.read_memory(r('rax'), r('rbx')).tobytes())
    except Exception as e:
        print("MD5_ERR", e)
  end
  continue
end

break *0x6ccac0
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if r('rsi') == 16 and 0 < r('rbx') < 20000:
    try:
        open('/tmp/aes_key.bin','wb').write(inf.read_memory(r('rdi'), 16).tobytes())
    except Exception as e:
        print("AES_ERR", e)
  end
  continue
end

break *0x5cc120
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if 0 < r('rsi') <= 512:
    try:
        open('/tmp/rsa_input.bin','wb').write(inf.read_memory(r('rdi'), r('rsi')).tobytes())
        pk = r('rcx')
        def dump_n(label, nptr):
            nat_ptr = int.from_bytes(inf.read_memory(nptr+8, 8).tobytes(), 'little')
            nat_len = int.from_bytes(inf.read_memory(nptr+16, 8).tobytes(), 'little')
            limbs = inf.read_memory(nat_ptr, nat_len*8).tobytes()
            nb = int.from_bytes(limbs, 'little').to_bytes(128, 'big')
            open('/tmp/rsa_n_%s.bin' % label, 'wb').write(nb)
        dump_n("1", int.from_bytes(inf.read_memory(pk, 8).tobytes(), 'little'))
        dump_n("2", int.from_bytes(inf.read_memory(pk+16, 8).tobytes(), 'little'))
    except Exception as e:
        print("RSA_ERR", e)
  end
  continue
end
run
