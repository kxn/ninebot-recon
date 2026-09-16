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
        data = inf.read_memory(r('rax'), r('rbx')).tobytes()
        open('/tmp/cc_input.bin','wb').write(data)
        print("CC_INPUT dumped %d" % len(data))
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
        data = inf.read_memory(r('rax'), r('rbx')).tobytes()
        open('/tmp/wrapper_md5.bin','wb').write(data)
        print("WRAPPER dumped %d" % len(data))
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
        print("AES key+plain dumped")
    except Exception as e:
        print("AES_ERR", e)
  end
  continue
end
run
