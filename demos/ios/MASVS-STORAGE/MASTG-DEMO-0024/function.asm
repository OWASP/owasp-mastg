            ;-- section.0.__TEXT.__text:
            ;-- func.100004000:
            ; UNKNOWN XREF from segment.__TEXT @ +0xd0
            ; CALL XREF from sym.func.100005a1c @ 0x100005aac
┌ 1060: sym.__s10MASTestApp9MastgTestV05mastgD010completionyySSc_tFZ (int64_t arg1, int64_t arg2, int64_t arg_1f0h);
│           0x100004000      sub sp, sp, 0x1f0                         ; [00] -r-x section size 34468 named 0.__TEXT.__text
│           0x100004004      stp x20, x19, [var_1d0h]
│           0x100004008      stp x29, x30, [var_1e0h]
│           0x10000400c      add x29, var_1e0h
│           0x100004010      stur x0, [var_bp_b0h]                     ; arg1
│           0x100004014      stur x1, [var_bp_a0h]                     ; arg2
│           0x100004018      movz w8, 0x8
│           0x10000401c      mov x2, x8
│           0x100004020      str x2, [var_78h]
│           0x100004024      adrp x8, segment.__DATA_CONST             ; 0x100010000
│           0x100004028      ldr x8, [x8, 0x4b0]                       ; 0xcf ; 207
│           0x10000402c      add x8, x8, 8
│           0x100004030      str x8, [var_40h]
│           0x100004034      adrp x8, segment.__DATA_CONST             ; 0x100010000
│           0x100004038      ldr x8, [x8, 0x3c0]                       ; 0xcf ; 207
│           0x10000403c      str x8, [var_e8h]
│           0x100004040      adrp x8, segment.__DATA_CONST             ; 0x100010000
│           0x100004044      ldr x8, [x8, 0x480]                       ; 0xcf ; 207
│           0x100004048      str x8, [var_f0h]
│           0x10000404c      adrp x8, segment.__DATA_CONST             ; 0x100010000
│           0x100004050      ldr x8, [x8, 0x4c8]                       ; 0xcf ; 207
│           0x100004054      stur x8, [var_bp_e8h]
│           0x100004058      stur xzr, [var_0h]
│           0x10000405c      stur xzr, [var_0h_2]
│           0x100004060      stur xzr, [var_0h_3]
│           0x100004064      stur xzr, [var_0h_4]
│           0x100004068      stur x0, [var_0h]                         ; arg1
│           0x10000406c      stur x1, [var_0h_2]                       ; arg2
│           0x100004070      adrp x0, 0x10000c000
│           0x100004074      add x0, x0, 0xb90                         ; 0x10000cb90 ; "TOKEN=123"
│           0x100004078      movz w8, 0x9
│           0x10000407c      mov x1, x8
│           0x100004080      movz w8, 0x1
│           0x100004084      stur w8, [var_d4h]
│           0x100004088      and w2, w8, 1
│           0x10000408c      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x100004090      str x0, [var_e0h]
│           0x100004094      mov x8, x1
│           0x100004098      ldr x1, [var_40h]                         ; 4
│           0x10000409c      stur x8, [var_98h]
│           0x1000040a0      stur x0, [var_0h_3]
│           0x1000040a4      stur x8, [var_0h_4]
│           0x1000040a8      movz w8, 0x1
│           0x1000040ac      mov x0, x8
│           0x1000040b0      str x0, [var_c8h]
│           0x1000040b4      bl sym Swift._allocateUninitializedArray<A>(Builtin.Word) -> (Swift.Array<A>, Builtin.RawPointer) ; sym.imp.Swift._allocateUninitializedArray_A__Builtin.Word______Swift.Array_A___Builtin.RawPointer_
│           0x1000040b8      str x0, [var_sp_38h]
│           0x1000040bc      mov x8, x1
│           0x1000040c0      ldr x1, [var_c8h]                         ; 0x4 ; 4
│           0x1000040c4      str x8, [var_30h]
│           0x1000040c8      movz w8, 0x13
│           0x1000040cc      mov x0, x8
│           0x1000040d0      str x0, [var_68h]
│           0x1000040d4      bl sym Swift.DefaultStringInterpolation.init(literalCapacity: Swift.Int, interpolationCount: Swift.Int) -> Swift.DefaultStringInterpolation ; sym.imp.Swift.DefaultStringInterpolation.init_literalCapacity:_Swift.Int__interpolationCount:_Swift.Int_____Swift.DefaultStringInterpolation
│           0x1000040d8      ldur w8, [var_d4h]
│           0x1000040dc      mov x9, x1
│           0x1000040e0      ldr x1, [var_78h]                         ; 0x4 ; 4
│           0x1000040e4      sub x20, var_bp_40h
│           0x1000040e8      str x20, [var_18h]
│           0x1000040ec      stur x0, [var_bp_40h]
│           0x1000040f0      stur x9, [var_38h]
│           0x1000040f4      adrp x0, 0x10000c000
│           0x1000040f8      add x0, x0, 0xb9a                         ; 0x10000cb9a ; "Leaking "
│           0x1000040fc      str x0, [var_70h]
│           0x100004100      and w2, w8, 1
│           0x100004104      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x100004108      str x1, [var_8h]
│           0x10000410c      bl sym Swift.DefaultStringInterpolation.appendLiteral(Swift.String) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendLiteral_Swift.String_______
│           0x100004110      ldr x20, [var_18h]                        ; 0x4 ; 4
│           0x100004114      ldr x0, [var_8h]                          ; 0x4 ; 4
│           0x100004118      bl sym.imp.swift_bridgeObjectRelease
│           0x10000411c      ldr x9, [var_e0h]                         ; 0x4 ; 4
│           0x100004120      ldr x1, [var_e8h]                         ; 0x4 ; 4
│           0x100004124      ldr x2, [var_f0h]                         ; 0x4 ; 4
│           0x100004128      ldur x3, [var_bp_e8h]
│           0x10000412c      ldur x8, [var_98h]
│           0x100004130      sub x0, var_50h
│           0x100004134      stur x9, [var_50h]
│           0x100004138      stur x8, [var_0h_5]
│           0x10000413c      bl sym Swift.DefaultStringInterpolation.appendInterpolation<A where A: Swift.CustomStringConvertible, A: Swift.TextOutputStreamable>(A) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendInterpolation_A_where_A:_Swift.CustomStringConvertible__A:_Swift.TextOutputStreamable__A_______
│           0x100004140      ldr x20, [var_18h]                        ; 0x4 ; 4
│           0x100004144      ldur w8, [var_d4h]
│           0x100004148      adrp x0, 0x10000c000
│           0x10000414c      add x0, x0, 0xba3                         ; 0x10000cba3 ; " from print"
│           0x100004150      movz w9, 0xb
│           0x100004154      mov x1, x9
│           0x100004158      str x1, [var_88h]
│           0x10000415c      and w2, w8, 1
│           0x100004160      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x100004164      str x1, [var_10h]
│           0x100004168      bl sym Swift.DefaultStringInterpolation.appendLiteral(Swift.String) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendLiteral_Swift.String_______
│           0x10000416c      ldr x0, [var_10h]                         ; 0x4 ; 4
│           0x100004170      bl sym.imp.swift_bridgeObjectRelease
│           0x100004174      ldur x8, [var_bp_40h]
│           0x100004178      str x8, [var_28h]
│           0x10000417c      ldur x0, [var_38h]
│           0x100004180      str x0, [var_20h]
│           0x100004184      bl sym.imp.swift_bridgeObjectRetain
│           0x100004188      ldr x0, [var_18h]                         ; 0x4 ; 4 ; int64_t arg1
│           0x10000418c      bl sym.__ss26DefaultStringInterpolationVWOh
│           0x100004190      ldr x1, [var_20h]                         ; 0x4 ; 4
│           0x100004194      ldr x0, [var_28h]                         ; 0x4 ; 4
│           0x100004198      bl sym Swift.String.init(stringInterpolation: Swift.DefaultStringInterpolation) -> Swift.String ; sym.imp.Swift.String.init_stringInterpolation:_Swift.DefaultStringInterpolation_____Swift.String
│           0x10000419c      ldr x9, [var_30h]                         ; 0x4 ; 4
│           0x1000041a0      ldr x11, [var_e8h]                        ; 0x4 ; 4
│           0x1000041a4      mov x10, x0
│           0x1000041a8      ldr x0, [var_sp_38h]                      ; 0x4 ; 4 ; int64_t arg1
│           0x1000041ac      mov x8, x1
│           0x1000041b0      ldr x1, [var_40h]                         ; 4 ; int64_t arg2
│           0x1000041b4      str x11, [x9, 0x18]
│           0x1000041b8      str x10, [x9]
│           0x1000041bc      str x8, [x9, 8]
│           0x1000041c0      bl sym.__ss27_finalizeUninitializedArrayySayxGABnlF
│           0x1000041c4      str x0, [var_60h]
│           0x1000041c8      bl sym.__ss5print_9separator10terminatoryypd_S2StFfA0_
│           0x1000041cc      str x0, [var_48h]
│           0x1000041d0      str x1, [var_58h]
│           0x1000041d4      bl sym.__ss5print_9separator10terminatoryypd_S2StFfA1_
│           0x1000041d8      ldr x2, [var_58h]                         ; 0x4 ; 4
│           0x1000041dc      mov x3, x0
│           0x1000041e0      ldr x0, [var_60h]                         ; 0x4 ; 4
│           0x1000041e4      mov x4, x1
│           0x1000041e8      ldr x1, [var_48h]                         ; 4
│           0x1000041ec      str x4, [var_sp_50h]
│           0x1000041f0      bl sym Swift.print(_: Any..., separator: Swift.String, terminator: Swift.String) -> () ; sym.imp.Swift.print__:_Any...__separator:_Swift.String__terminator:_Swift.String_______
│           0x1000041f4      ldr x0, [var_sp_50h]                      ; 0x4 ; 4
│           0x1000041f8      bl sym.imp.swift_bridgeObjectRelease
│           0x1000041fc      ldr x0, [var_58h]                         ; 0x4 ; 4
│           0x100004200      bl sym.imp.swift_bridgeObjectRelease
│           0x100004204      ldr x0, [var_60h]                         ; 0x4 ; 4
│           0x100004208      bl sym.imp.swift_bridgeObjectRelease
│           0x10000420c      ldr x0, [var_68h]                         ; 0x4 ; 4
│           0x100004210      ldr x1, [var_c8h]                         ; 0x4 ; 4
│           0x100004214      bl sym Swift.DefaultStringInterpolation.init(literalCapacity: Swift.Int, interpolationCount: Swift.Int) -> Swift.DefaultStringInterpolation ; sym.imp.Swift.DefaultStringInterpolation.init_literalCapacity:_Swift.Int__interpolationCount:_Swift.Int_____Swift.DefaultStringInterpolation
│           0x100004218      ldur w8, [var_d4h]
│           0x10000421c      mov x10, x0
│           0x100004220      ldr x0, [var_70h]                         ; 0x4 ; 4
│           0x100004224      mov x9, x1
│           0x100004228      ldr x1, [var_78h]                         ; 0x4 ; 4
│           0x10000422c      sub x20, var_bp_60h
│           0x100004230      str x20, [var_sp_98h]
│           0x100004234      stur x10, [var_bp_60h]
│           0x100004238      stur x9, [var_bp_58h]
│           0x10000423c      and w2, w8, 1
│           0x100004240      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x100004244      str x1, [var_80h]
│           0x100004248      bl sym Swift.DefaultStringInterpolation.appendLiteral(Swift.String) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendLiteral_Swift.String_______
│           0x10000424c      ldr x20, [var_sp_98h]                     ; 0x4 ; 4
│           0x100004250      ldr x0, [var_80h]                         ; 0x4 ; 4
│           0x100004254      bl sym.imp.swift_bridgeObjectRelease
│           0x100004258      ldr x9, [var_e0h]                         ; 0x4 ; 4
│           0x10000425c      ldr x1, [var_e8h]                         ; 0x4 ; 4
│           0x100004260      ldr x2, [var_f0h]                         ; 0x4 ; 4
│           0x100004264      ldur x3, [var_bp_e8h]
│           0x100004268      ldur x8, [var_98h]
│           0x10000426c      sub x0, var_bp_70h
│           0x100004270      stur x9, [var_bp_70h]
│           0x100004274      stur x8, [var_0h_6]
│           0x100004278      bl sym Swift.DefaultStringInterpolation.appendInterpolation<A where A: Swift.CustomStringConvertible, A: Swift.TextOutputStreamable>(A) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendInterpolation_A_where_A:_Swift.CustomStringConvertible__A:_Swift.TextOutputStreamable__A_______
│           0x10000427c      ldr x20, [var_sp_98h]                     ; 0x4 ; 4
│           0x100004280      ldr x1, [var_88h]                         ; 0x4 ; 4
│           0x100004284      ldur w8, [var_d4h]
│           0x100004288      adrp x0, 0x10000c000
│           0x10000428c      add x0, x0, 0xbaf                         ; 0x10000cbaf ; " from NSLog"
│           0x100004290      and w2, w8, 1
│           0x100004294      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x100004298      str x1, [var_90h]
│           0x10000429c      bl sym Swift.DefaultStringInterpolation.appendLiteral(Swift.String) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendLiteral_Swift.String_______
│           0x1000042a0      ldr x0, [var_90h]                         ; 0x4 ; 4
│           0x1000042a4      bl sym.imp.swift_bridgeObjectRelease
│           0x1000042a8      ldur x8, [var_bp_60h]
│           0x1000042ac      str x8, [var_a8h]
│           0x1000042b0      ldur x0, [var_bp_58h]
│           0x1000042b4      str x0, [var_a0h]
│           0x1000042b8      bl sym.imp.swift_bridgeObjectRetain
│           0x1000042bc      ldr x0, [var_sp_98h]                      ; 0x4 ; 4 ; int64_t arg1
│           0x1000042c0      bl sym.__ss26DefaultStringInterpolationVWOh
│           0x1000042c4      ldr x1, [var_a0h]                         ; 0x4 ; 4
│           0x1000042c8      ldr x0, [var_a8h]                         ; 0x4 ; 4
│           0x1000042cc      bl sym Swift.String.init(stringInterpolation: Swift.DefaultStringInterpolation) -> Swift.String ; sym.imp.Swift.String.init_stringInterpolation:_Swift.DefaultStringInterpolation_____Swift.String
│           0x1000042d0      str x0, [var_b0h]
│           0x1000042d4      str x1, [var_c0h]
│           0x1000042d8      adrp x0, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x1000042dc      add x0, x0, 0xc8                          ; 0x1000140c8
│                                                                      ; sym.__ss7CVarArg_pMD ; int64_t arg1
│           0x1000042e0      bl sym.___swift_instantiateConcreteTypeFromMangledName
│           0x1000042e4      mov x1, x0
│           0x1000042e8      movz x0, 0
│           0x1000042ec      stur x0, [var_bp_e0h]
│           0x1000042f0      bl sym Swift._allocateUninitializedArray<A>(Builtin.Word) -> (Swift.Array<A>, Builtin.RawPointer) ; sym.imp.Swift._allocateUninitializedArray_A__Builtin.Word______Swift.Array_A___Builtin.RawPointer_
│           0x1000042f4      ldr x1, [var_c0h]                         ; 0x4 ; 4
│           0x1000042f8      mov x2, x0
│           0x1000042fc      ldr x0, [var_b0h]                         ; 0x4 ; 4
│           0x100004300      str x2, [var_b8h]
│           0x100004304      bl sym.imp.Foundation.NSLog_Swift.String__Swift.CVarArg..._______
│           0x100004308      ldr x0, [var_b8h]                         ; 0x4 ; 4
│           0x10000430c      bl sym.imp.swift_bridgeObjectRelease
│           0x100004310      ldr x0, [var_c0h]                         ; 0x4 ; 4
│           0x100004314      bl sym.imp.swift_bridgeObjectRelease
│           0x100004318      ldur x0, [var_bp_a0h]
│           0x10000431c      bl sym.imp.swift_retain
│           0x100004320      ldr x1, [var_c8h]                         ; 0x4 ; 4
│           0x100004324      movz w8, 0x1c
│           0x100004328      mov x0, x8
│           0x10000432c      str x0, [var_d0h]
│           0x100004330      bl sym Swift.DefaultStringInterpolation.init(literalCapacity: Swift.Int, interpolationCount: Swift.Int) -> Swift.DefaultStringInterpolation ; sym.imp.Swift.DefaultStringInterpolation.init_literalCapacity:_Swift.Int__interpolationCount:_Swift.Int_____Swift.DefaultStringInterpolation
│           0x100004334      ldur w8, [var_d4h]
│           0x100004338      mov x9, x1
│           0x10000433c      ldr x1, [var_d0h]                         ; 0x4 ; 4
│           0x100004340      sub x20, var_bp_80h
│           0x100004344      stur x20, [var_bp_c8h]
│           0x100004348      stur x0, [var_bp_80h]
│           0x10000434c      stur x9, [var_bp_78h]
│           0x100004350      adrp x0, 0x10000c000
│           0x100004354      add x0, x0, 0xbc0                         ; 0x10000cbc0 ; "Succesfully logged a token: "
│           0x100004358      and w2, w8, 1
│           0x10000435c      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x100004360      str x1, [var_d8h]
│           0x100004364      bl sym Swift.DefaultStringInterpolation.appendLiteral(Swift.String) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendLiteral_Swift.String_______
│           0x100004368      ldur x20, [var_bp_c8h]
│           0x10000436c      ldr x0, [var_d8h]                         ; 0x4 ; 4
│           0x100004370      bl sym.imp.swift_bridgeObjectRelease
│           0x100004374      ldr x9, [var_e0h]                         ; 0x4 ; 4
│           0x100004378      ldr x1, [var_e8h]                         ; 0x4 ; 4
│           0x10000437c      ldr x2, [var_f0h]                         ; 0x4 ; 4
│           0x100004380      ldur x3, [var_bp_e8h]
│           0x100004384      ldur x8, [var_98h]
│           0x100004388      sub x0, var_bp_90h
│           0x10000438c      stur x9, [var_bp_90h]
│           0x100004390      stur x8, [var_0h_7]
│           0x100004394      bl sym Swift.DefaultStringInterpolation.appendInterpolation<A where A: Swift.CustomStringConvertible, A: Swift.TextOutputStreamable>(A) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendInterpolation_A_where_A:_Swift.CustomStringConvertible__A:_Swift.TextOutputStreamable__A_______
│           0x100004398      ldur x20, [var_bp_c8h]
│           0x10000439c      ldur x1, [var_bp_e0h]
│           0x1000043a0      ldur w8, [var_d4h]
│           0x1000043a4      adrp x0, 0x10000c000
│           0x1000043a8      add x0, x0, 0xc38
│           0x1000043ac      and w2, w8, 1
│           0x1000043b0      bl sym Swift.String.init(_builtinStringLiteral: Builtin.RawPointer, utf8CodeUnitCount: Builtin.Word, isASCII: Builtin.Int1) -> Swift.String ; sym.imp.Swift.String.init__builtinStringLiteral:_Builtin.RawPointer__utf8CodeUnitCount:_Builtin.Word__isASCII:_Builtin.Int1_____Swift.String
│           0x1000043b4      stur x1, [var_bp_d0h]
│           0x1000043b8      bl sym Swift.DefaultStringInterpolation.appendLiteral(Swift.String) -> () ; sym.imp.Swift.DefaultStringInterpolation.appendLiteral_Swift.String_______
│           0x1000043bc      ldur x20, [var_bp_a0h]
│           0x1000043c0      ldur x0, [var_bp_d0h]
│           0x1000043c4      bl sym.imp.swift_bridgeObjectRelease
│           0x1000043c8      ldur x8, [var_bp_80h]
│           0x1000043cc      stur x8, [var_bp_b8h]
│           0x1000043d0      ldur x0, [var_bp_78h]
│           0x1000043d4      stur x0, [var_bp_c0h]
│           0x1000043d8      bl sym.imp.swift_bridgeObjectRetain
│           0x1000043dc      ldur x0, [var_bp_c8h]                     ; int64_t arg1
│           0x1000043e0      bl sym.__ss26DefaultStringInterpolationVWOh
│           0x1000043e4      ldur x1, [var_bp_c0h]
│           0x1000043e8      ldur x0, [var_bp_b8h]
│           0x1000043ec      bl sym Swift.String.init(stringInterpolation: Swift.DefaultStringInterpolation) -> Swift.String ; sym.imp.Swift.String.init_stringInterpolation:_Swift.DefaultStringInterpolation_____Swift.String
│           0x1000043f0      ldur x8, [var_bp_b0h]
│           0x1000043f4      stur x1, [var_bp_a8h]
│           0x1000043f8      blr x8
│           0x1000043fc      ldur x0, [var_bp_a8h]
│           0x100004400      bl sym.imp.swift_bridgeObjectRelease
│           0x100004404      ldur x0, [var_bp_a0h]
│           0x100004408      bl sym.imp.swift_release
│           0x10000440c      ldur x0, [var_98h]
│           0x100004410      bl sym.imp.swift_bridgeObjectRelease
│           0x100004414      ldp x29, x30, [var_1e0h]
│           0x100004418      ldp x20, x19, [var_1d0h]
│           0x10000441c      add sp, arg_1f0h
└           0x100004420      ret
