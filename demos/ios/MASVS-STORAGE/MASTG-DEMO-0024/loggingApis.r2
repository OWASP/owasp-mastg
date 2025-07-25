e asm.bytes = false
e scr.color=false
e asm.var=false

!printf "Uses of NSLog:\n"
afl~NSLog

!printf "\n"

!printf "xrefs to NSLog:\n"
axt @ 0x10000c6a4

!printf "\n"
!printf "Invocation of NSLog:\n"

pd-- 5 @ 0x100004304

pdf @ 0x1000042f4 > function.asm
