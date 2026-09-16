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
        print("CC_INPUT dumped")
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
        print("WRAPPER dumped")
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
        open('/tmp/aes_plain.bin','wb').write(inf.read_memory(r('rax'), r('rbx')).tobytes())
        print("AES dumped")
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
# rdi/rsi = msg, rcx = pub(?), 打印全部候选
if 0 < r('rsi') <= 512:
    try:
        open('/tmp/rsa_input.bin','wb').write(inf.read_memory(r('rdi'), r('rsi')).tobytes())
        print("RSA_INPUT dumped %d" % r('rsi'))
    except Exception as e:
        print("RSA_ERR", e)
  end
  continue
end
run
