set pagination off
set confirm off
set breakpoint pending on
break *0x5d1780
commands
  silent
  set $len = $rbx
  printf "MD5SUM len=%d ptr=%p\n", $len, $rax
  if $len > 0 && $len < 10000
    dump binary memory /tmp/wrapper_md5.bin $rax $rax+$len
  end
  continue
end
run
