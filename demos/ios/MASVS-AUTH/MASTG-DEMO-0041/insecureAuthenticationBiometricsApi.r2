e asm.bytes=false
e scr.color=false
e asm.var=false

?e Print xrefs to \'Run analysis\"
aaa

?e Print xrefs to \'evaluatePolicy\"
f~evaluatePolicy

?e

?e Print xrefs to 0x100010098
axt @ 0x100010098

?e

?e Print disassembly around \"evaluatePolicy\" in the function
pdf @ 0x100004344 | grep -C 5 "evaluatePolicy:"

?e Print xrefs to \'SecAccessControlCreateWithFlags\"
f~SecAccessControlCreateWithFlags
