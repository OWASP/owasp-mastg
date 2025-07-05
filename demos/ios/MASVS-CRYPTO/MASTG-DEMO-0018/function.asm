            ; CODE XREFS from sym.func.100004000 @ 0x100004050, 0x100004054
┌ 148: fcn.100004058 (int64_t arg5, int64_t arg_20h, int64_t arg_30h, int64_t arg_40h, int64_t arg_50h, int64_t arg_60h, int64_t arg_70h, int64_t arg_80h);
│           0x100004058      ubfx x25, x4, 0x30, 8                     ; arg5
│       ┌─< 0x10000405c      b 0x100004080
..
│    ││││   ; CODE XREF from fcn.100004058 @ 0x10000405c
│    │└─└─> 0x100004080      ldr x28, [x26]                            ; 0xe1 ; 225
│    │ │    0x100004084      ldr x27, [x28, 0x10]                      ; 0xe3 ; 227
│    │ │    0x100004088      mov x0, x28
│    │ │    0x10000408c      bl sym.imp.swift_isUniquelyReferenced_nonNull_native
│    │ │    0x100004090      str x28, [x26]
│    │ │┌─< 0x100004094      tbnz w0, 0, 0x1000040b0
│    │ ││   0x100004098      movz w0, 0
│    │ ││   0x10000409c      mov x1, x27                               ; int64_t arg2
│    │ ││   0x1000040a0      movz w2, 0
│    │ ││   0x1000040a4      mov x3, x28
│    │ ││   0x1000040a8      bl sym.func.1000045dc
│    │ ││   0x1000040ac      mov x28, x0
│    │ │└─> 0x1000040b0      str x28, [x26]
│    │ │    0x1000040b4      add x8, x28, 0x20
│    │ │    0x1000040b8      stp x27, x24, [sp, 8]
│    │ │    0x1000040bc      str x8, [sp]
│    │ │    0x1000040c0      movz w0, 0
│    │ │    0x1000040c4      movz w1, 0x2
│    │ │    0x1000040c8      movz w2, 0x1
│    │ │    0x1000040cc      mov x3, x23
│    │ │    0x1000040d0      movz w4, 0x18
│    │ │    0x1000040d4      movz x5, 0
│    │ │    0x1000040d8      mov x6, x22
│    │ │    0x1000040dc      mov x7, x25
│    │ │    0x1000040e0      bl sym.imp.CCCrypt
│    │ │    0x1000040e4      str w0, [x20]
│    │ │    0x1000040e8      mov x21, x19
│    │ │    0x1000040ec      ldp x29, x30, [arg_70h]
│    │ │    0x1000040f0      ldp x20, x19, [arg_60h]
│    │ │    0x1000040f4      ldp x23, x22, [arg_50h]
│    │ │    0x1000040f8      ldp x25, x24, [arg_40h]
│    │ │    0x1000040fc      ldp x27, x26, [arg_30h]
│    │ │    0x100004100      ldr x28, [arg_20h]                        ; 0x4 ; 4
│    │ │    0x100004104      add sp, arg_80h
└    │ │    0x100004108      ret
