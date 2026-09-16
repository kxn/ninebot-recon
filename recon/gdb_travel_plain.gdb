set pagination off
set confirm off
set breakpoint pending on
set $seq = 0

break *0x6ccac0
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if r('rsi') == 16 and 0 < r('rbx') < 50000:
    gdb.execute("set $seq = $seq + 1")
    seq = int(gdb.parse_and_eval('$seq'))
    try:
        plain = bytes(inf.read_memory(r('rax'), r('rbx')).tobytes())
        key = bytes(inf.read_memory(r('rdi'), 16).tobytes())
        open('/tmp/wrapper_latest.bin', 'wb').write(plain)
        open('/tmp/aes_plain_%d.bin' % seq, 'wb').write(plain)
        open('/tmp/aes_key_%d.bin' % seq, 'wb').write(key)
        print("AES_PLAIN_%d len=%d" % (seq, len(plain)))
    except Exception as e:
        print("AES_ERR", e)
  end
  continue
end

run
