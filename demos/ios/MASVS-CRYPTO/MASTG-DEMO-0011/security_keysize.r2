!printf "\n\n"

!printf "Uses of SecKeyCreateRandomKey:\n"
afl~SecKeyCreateRandomKey

!printf "\n"

!printf "xrefs to SecKeyCreateRandomKey:\n"
axt @ 0x1000078ac

!printf "\n"

!printf "Use of reloc.kSecAttrKeySizeInBits as input for SecKeyCreateRandomKey:\n"
pd 1 @ sym.func.1000046f8

!printf "...\n"

pd 9 @ 0x10000484c

!printf "...\n"

pd-- 2 @ 0x1000049a0

