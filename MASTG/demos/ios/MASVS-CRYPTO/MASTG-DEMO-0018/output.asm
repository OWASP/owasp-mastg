Uses of the CCCrypt function:
0x1000076c4    1     12 sym.imp.CCCrypt

xrefs to CCCrypt:
sym.func.100004000 0x1000040e0 [CALL:--x] bl sym.imp.CCCrypt

Use of CCCrypt:
│           0x1000040bc      str x8, [sp]
│           0x1000040c0      mov w0, 0
│           0x1000040c4      mov w1, 2
│           0x1000040c8      mov w2, 1
│           0x1000040cc      mov x3, x23
│           0x1000040d0      mov w4, 0x18
│           0x1000040d4      mov x5, 0
│           0x1000040d8      mov x6, x22
│           0x1000040dc      mov x7, x25
│           0x1000040e0      bl sym.imp.CCCrypt                        ; CCCryptorStatus CCCrypt(CCOperation op, CCAlgorithm alg, int32_t options, const void *key, uint32_t keyLength, const void *iv, const void *dataIn, uint32_t dataInLength, void *dataOut, uint32_t dataOutAvailable, uint32_t *dataOutMoved)
│           0x1000040e4      str w0, [x20]
│           0x1000040e8      mov x21, x19
│           0x1000040ec      ldp x29, x30, [var_70h]
│           0x1000040f0      ldp x20, x19, [var_60h]
│           0x1000040f4      ldp x23, x22, [var_50h]
│           0x1000040f8      ldp x25, x24, [var_40h]
│           0x1000040fc      ldp x27, x26, [var_30h]
│           0x100004100      ldr x28, [var_20h]
