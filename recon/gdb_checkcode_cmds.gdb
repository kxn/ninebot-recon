set pagination off
set confirm off
set breakpoint pending on
break *0x6cac40
commands
  silent
  printf "CHECKCODE len=%d ptr=%p\n", $rbx, $rax
  if $rbx > 0 && $rbx < 20000
    dump binary memory /tmp/checkcode_input.bin $rax $rax+$rbx
  end
  continue
end
run
