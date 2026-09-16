set pagination off
set confirm off
set breakpoint pending on
set env NINECLI_CONFIG /tmp/ninecli_gdb_config

python
import gdb, os
counters = {"cc": 0, "aes": 0, "md5": 0}
def dump(label, ptr, ln, tag):
    if not (0 < ln < 20000):
        return
    try:
        inf = gdb.selected_inferior()
        data = inf.read_memory(ptr, ln).tobytes()
        counters[label] += 1
        n = counters[label]
        path = "/tmp/gdb_%s_%s_%d.bin" % (label, tag, n)
        open(path, "wb").write(data)
        print("GDB_DUMP %s %s len=%d -> %s" % (label, tag, ln, path))
    except Exception as e:
        print("GDB_ERR", label, e)
end

break *0x6cac40
commands
  silent
  python
import gdb
r = lambda n: int(gdb.parse_and_eval('$'+n))
dump("cc", r('rax'), r('rbx'), "all")
  end
  continue
end

break *0x6ccac0
commands
  silent
  python
import gdb
r = lambda n: int(gdb.parse_and_eval('$'+n))
if r('rsi') == 16:
    dump("aes", r('rdi'), 16, "all")
dump("wrap", r('rax'), r('rbx'), "all")
  end
  continue
end

break *0x5d1780
commands
  silent
  python
import gdb
r = lambda n: int(gdb.parse_and_eval('$'+n))
dump("md5", r('rax'), r('rbx'), "all")
  end
  continue
end
run
