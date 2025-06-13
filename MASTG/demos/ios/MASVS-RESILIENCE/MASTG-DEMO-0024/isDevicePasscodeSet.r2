e asm.bytes=false
e scr.color=false
e asm.var=false

?e Print xrefs to \'canEvaluatePolicy\"
f~canEvaluatePolicy

?e

?e Print xrefs to 0x100008360
axt @ 0x100008360

?e

?e Print xrefs to 0x1000100a0
axt @ 0x1000100a0

?e

?e Print disassembly around \"canEvaluatePolicy\" in the function
pdf @ 0x100004f10 | grep -C 5 "canEvaluatePolicy:error:"
