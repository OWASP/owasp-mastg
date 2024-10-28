e asm.bytes = false
e scr.color=false
e asm.var=false

!printf "Uses of the CCCrypt function:\n"
afl~CCCrypt

!printf "\n"

!printf "xrefs to CCCrypt:\n"
axt @ 0x1000076c4

!printf "\n"

!printf "Use of CCCrypt:\n"

# Seek to the function where CCCrypt is called (Replace with the address found from axt output)
pd-- 9 @ 0x1000040e0

pdf @ sym.func.100004000 > function.asm
