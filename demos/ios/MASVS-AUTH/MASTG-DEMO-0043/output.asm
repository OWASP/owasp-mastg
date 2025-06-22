Print xrefs to 'Run analysis"
Print xrefs to 'SecAccessControlCreateWithFlags"
sym.MASTestApp.MastgTest.createAccessControl.Sec.Ref.d_n 0x100004194 [CALL:--x] bl sym.imp.SecAccessControlCreateWithFlags

Print disassembly around "SecAccessControlCreateWithFlags" in the function
│           0x100004180      mov x19, x0
│           0x100004184      add x3, sp, 0x10
│           0x100004188      mov x0, 0
│           0x10000418c      mov x1, x19
│           0x100004190      mov w2, 1
│           0x100004194      bl sym.imp.SecAccessControlCreateWithFlags
│       ┌─< 0x100004198      cbz x0, 0x1000041ac
│       │   0x10000419c      mov x20, x0
│       │   0x1000041a0      mov x0, x19                               ; void *instance
│       │   0x1000041a4      bl sym.imp.objc_release                   ; void objc_release(void *instance)
│      ┌──< 0x1000041a8      b 0x100004310
