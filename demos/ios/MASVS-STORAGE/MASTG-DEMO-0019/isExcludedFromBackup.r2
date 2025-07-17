e asm.bytes=false
e scr.color=false
e asm.var=false

?e Uses of isExcludedFromBackup:
afl~isExcludedFromBackup

?e

?e xrefs to isExcludedFromBackup:
axt @ 0x10000cc28

?e
?e Use of isExcludedFromBackup:

pd-- 5 @ 0x100004594

?e
?e Search for secret.txt:
/ secret.txt

?e
?e Use of the string secret.txt:
pd-- 5 @ 0x10000443c

pdf @ 0x100004594 > function.asm
