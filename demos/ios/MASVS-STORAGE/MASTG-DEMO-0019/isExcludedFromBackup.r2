e asm.bytes = false
e scr.color=false
e asm.var=false

!printf "Uses of isExcludedFromBackup:\n"
afl~isExcludedFromBackup

!printf "\n"

!printf "xrefs to isExcludedFromBackup:\n"
axt @ 0x10000cc28

!printf "\n"
!printf "Use of isExcludedFromBackup:\n"

pd-- 5 @ 0x100004594

!printf "\n"
!printf "Search for secret.txt"
/ secret.txt

!printf "\n"
!printf "Use of the string secret.txt:\n"
pd-- 5 @ 0x10000443c


pdf @ 0x100004594 > function.asm
