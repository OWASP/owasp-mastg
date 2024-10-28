e asm.bytes = false
e scr.color=false
e asm.var=false

!printf "Uses of SecKeyCreateWithData:\n"
afl~SecKeyCreateWithData

!printf "\n"

!printf "xrefs to SecKeyCreateWithData:\n"
axt @ 0x100007904

!printf "\n"

pdf @ sym.func.10000491c > function.asm

px 607 @ 0x1000100c8 > key.asm