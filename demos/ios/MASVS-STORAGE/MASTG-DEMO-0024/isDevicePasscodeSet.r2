e asm.bytes=false
e scr.color=false
e asm.var=false

aao
e asm.emu=true

?e Print xrefs to \'canEvaluatePolicy\"
f~str.canEvaluatePolicy:error:

?e Print xrefs to 0x100008360
axt 0x100008360

?e Print disassembly around \"canEvaluatePolicy\" in the function
pdf @ 0x100004f10 | grep -B 5 "canEvaluatePolicy:error:"
