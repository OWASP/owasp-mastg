Print xrefs to 'Run analysis"
Print xrefs to 'evaluatePolicy"
0x100008297 38 str.evaluatePolicy:localizedReason:reply:
0x100010098 8 reloc.fixup.evaluatePolicy:localizedReason:

Print xrefs to 0x100010098
sym.MASTestApp.MastgTest.mastg.completion.nd_n 0x100004344 [DATA:r--] ldr x1, [x8, 0x98]

Print disassembly around "evaluatePolicy" in the function
│           0x100004334      bl sym.imp.swift_retain
│           0x100004338      mov x0, x23                               ; void *arg0
│           0x10000433c      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
│                                                                      ; void swift_release(0)
│           0x100004340      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100010000
│           0x100004344      ldr x1, [x8, 0x98]                        ; [0x100010098:4]=0x8297 ; reloc.fixup.evaluatePolicy:localizedReason: ; char *selector
│           0x100004348      mov x0, x19                               ; void *instance
│           0x10000434c      mov w2, 1
│           0x100004350      mov x3, x20
│           0x100004354      mov x4, x22
│           0x100004358      bl sym.imp.objc_msgSend                   ; void *objc_msgSend(void *instance, char *selector)
Print xrefs to 'SecAccessControlCreateWithFlags"
