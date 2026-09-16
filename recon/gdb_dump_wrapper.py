#!/usr/bin/env python3
"""抓取二进制加密请求的明文 wrapper（md5.Sum 断点 @0x5d1780）。
用法: python3 gdb_dump_wrapper.py <outfile> -- <ninecli args...>
"""
import os
import subprocess
import sys

GDB_CMD = f"""
set pagination off
set confirm off
set breakpoint pending on
# 忽略 .gdbinit 报错
set print thread-events off
break *0x5d1780
commands
  silent
  set $len = $rbx
  printf "MD5SUM len=%d ptr=%p\\n", $len, $rax
  if $len > 0 && $len < 10000
    dump binary memory {sys.argv[1]} $rax $rax+$len
  end
  continue
end
run
"""

outfile = sys.argv[1]
args = sys.argv[2:]
if args and args[0] == "--":
    args = args[1:]

if os.path.exists(outfile):
    os.unlink(outfile)

cmd = ["gdb", "-q", "-batch",
       "-ex", "set pagination off",
       "-ex", "set confirm off",
       "-ex", "break *0x5d1780",
       "-ex", "commands",
       "-ex", "silent",
       "-ex", "set $len = $rbx",
       "-ex", "printf \"MD5SUM len=%d ptr=%p\\n\", $len, $rax",
       "-ex", f"dump binary memory {outfile} $rax $rax+$len",
       "-ex", "continue",
       "-ex", "end",
       "-ex", "run",
       "--args", "/data/dl/ninebot/ninecli_wheel/ninecli/bin/ninecli", *args]
print(" ".join(cmd))
r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
print(r.stdout[-4000:])
print(r.stderr[-2000:], file=sys.stderr)
print("EXIT", r.returncode, "| dump exists:", os.path.exists(outfile),
      os.path.getsize(outfile) if os.path.exists(outfile) else 0)
