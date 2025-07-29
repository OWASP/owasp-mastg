Uses of isExcludedFromBackup:
0x10000cc28    1     12 sym.imp.Foundation.URLResourceValues.isExcludedFromBackup...Sgvs

xrefs to isExcludedFromBackup:
sym.MASTestApp.MastgTest.mastg.completion...FZ 0x100004594 [CALL:--x] bl sym.imp.Foundation.URLResourceValues.isExcludedFromBackup...Sgvs

Use of isExcludedFromBackup:
│           0x100004580      ldr x8, [x8, 8]
│           0x100004584      blr x8
│           0x100004588      mov x8, x20
│           0x10000458c      bl sym.imp.Foundation.URLResourceValues...VACycfC...ycfC
│           0x100004590      mov w0, 1
│           0x100004594      bl sym Foundation.URLResourceValues.isExcludedFromBackup...Sgvs ; sym.imp.Foundation.URLResourceValues.isExcludedFromBackup...Sgvs
│           0x100004598      sub x8, x29, 8
│           0x10000459c      ldur x20, [x8, -0x100]
│           0x1000045a0      sub x8, x29, 0x88
│           0x1000045a4      ldur x8, [x8, -0x100]

Search for secret.txt:
0x10000dbe6 hit4_0 "lueFatal errorsecret.txt"

Use of the string secret.txt:
│           0x100004428      mov x0, x20
│           0x10000442c      blr x8
│           0x100004430      ldur x0, [x29, -0xe8]                     ; void *instance
│           0x100004434      bl sym.imp.objc_release                   ; void objc_release(void *instance)
│           0x100004438      adrp x0, sym.imp.swift_getObjCClassMetadata ; 0x10000d000
│           0x10000443c      add x0, x0, 0xbe6                         ; 0x10000dbe6 ; "secret.txt"
│           0x100004440      mov w8, 0xa
│           0x100004444      mov x1, x8
│           0x100004448      mov w8, 1
│           0x10000444c      sub x9, x29, 0xc4
