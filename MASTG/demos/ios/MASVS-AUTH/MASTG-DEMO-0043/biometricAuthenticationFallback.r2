e asm.bytes=false
e scr.color=false
e asm.var=false

?e Print xrefs to \'Run analysis\"
aaa

?e Print xrefs to \'SecAccessControlCreateWithFlags\"
axt @ sym.imp.SecAccessControlCreateWithFlags

?e

?e Print disassembly around \"SecAccessControlCreateWithFlags\" in the function
pdf @  0x100004194 | grep -C 5 "SecAccessControlCreateWithFlags"
