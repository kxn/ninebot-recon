set pagination off
set confirm off
set breakpoint pending on

# 0x6ceff8: EncodeOrderedJSON 返回后（rax/rbx = JSON 主体 string）
break *0x6ceff8
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if 0 < r('rbx') < 20000:
    try:
        d = bytes(inf.read_memory(r('rax'), r('rbx')).tobytes())
        open('/tmp/gdb_inner_body.bin','wb').write(d)
        print("INNER_BODY dumped %d" % len(d))
    except Exception as e:
        print("INNER_BODY_ERR", e)
  end
  continue
end

# 0x6cf040: BuildInner 返回前（0x45da80 concat 后，rax/rbx = 完整内层 string）
break *0x6cf040
commands
  silent
  python
import gdb
inf = gdb.selected_inferior()
r = lambda n: int(gdb.parse_and_eval('$'+n))
if 0 < r('rbx') < 20000:
    try:
        d = bytes(inf.read_memory(r('rax'), r('rbx')).tobytes())
        open('/tmp/gdb_inner_full.bin','wb').write(d)
        print("INNER_FULL dumped %d" % len(d))
    except Exception as e:
        print("INNER_FULL_ERR", e)
  end
  continue
end

run
