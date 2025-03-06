Print xrefs to 'canEvaluatePolicy"
0x100008360 24 str.canEvaluatePolicy:error:
Print xrefs to 0x100008360
(nofunc) 0x100000350 [UNKNOWN] invalid
sym.func.100004ea8 0x100004f10 [STRING] ldr x1, [x8, 0xa0]
Print disassembly around "canEvaluatePolicy" in the function
│           0x100004f0c      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100010000 ; x8=0x100010000 -> 0x81
│           0x100004f10      ldr x1, [x8, 0xa0]                        ; 0x100008360 ; char *selector ; tmp=0x1000100a0 ; x1=0x100008360 -> 0x456e6163 section.8.__TEXT.__objc_methname
│           0x100004f14      movz w2, 0x2                              ; w2=0x2
│           0x100004f18      movz x3, 0                                ; x3=0x0
│           0x100004f1c      bl sym.imp.objc_msgSend                   ; void *objc_msgSend(void *instance, char *selector) ; lr=0x100004f20 -> 0xaa0003f7 ; pc=0x100007794 "0"
│                                                                      ; void *objc_msgSend(-1, "canEvaluatePolicy:error:")
