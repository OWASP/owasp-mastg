            ; CALL XREF from sym.func.1000063c8 @ 0x100006400(x)
┌ 2444: sym.func.10000491c (int64_t arg1, int64_t arg2, void *arg3);
│           0x10000491c      stp x28, x27, [sp, -0x60]!
│           0x100004920      stp x26, x25, [var_10h]
│           0x100004924      stp x24, x23, [var_20h]
│           0x100004928      stp x22, x21, [var_30h]
│           0x10000492c      stp x20, x19, [var_40h]
│           0x100004930      stp x29, x30, [var_50h_2]
│           0x100004934      add x29, sp, 0x50
│           0x100004938      sub sp, sp, 0x1b0
│           0x10000493c      mov x19, sp
│           0x100004940      str x2, [x19, 0x70]                       ; arg3
│           0x100004944      mov x24, x1                               ; arg2
│           0x100004948      mov x26, x0                               ; arg1
│           0x10000494c      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004950      ldr x8, reloc.__stack_chk_guard           ; 0x10000c408
│           0x100004954      ldr x8, [x8]
│           0x100004958      stur x8, [x29, -0x60]
│           0x10000495c      mov x0, 0
│           0x100004960      bl sym Foundation...8EncodingVMa          ; sym.imp.Foundation...8EncodingVMa
│           0x100004964      ldur x8, [x0, -8]
│           0x100004968      stp x8, x0, [x19, 0x48]
│           0x10000496c      ldr x8, [x8, 0x40]
│           0x100004970      mov x9, x8
│           0x100004974      adrp x16, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004978      ldr x16, reloc.__chkstk_darwin            ; 0x10000c3f8
│           0x10000497c      blr x16
│           0x100004980      mov x9, sp
│           0x100004984      add x8, x8, 0xf
│           0x100004988      and x8, x8, 0xfffffffffffffff0
│           0x10000498c      sub x8, x9, x8
│           0x100004990      str x8, [x19, 0x58]
│           0x100004994      mov sp, x8
│           0x100004998      adrp x0, segment.__DATA                   ; 0x100010000
│           0x10000499c      add x0, x0, 0x328                         ; int64_t arg1
│           0x1000049a0      bl sym.func.1000052a8
│           0x1000049a4      adrp x1, segment.__DATA                   ; 0x100010000
│           0x1000049a8      add x1, x1, 0xa8
│           0x1000049ac      bl sym.imp.swift_initStaticObject
│           0x1000049b0      mov x20, x0
│           0x1000049b4      adrp x21, segment.__DATA                  ; 0x100010000
│           0x1000049b8      add x21, x21, 0x330
│           0x1000049bc      mov x0, x21                               ; int64_t arg1
│           0x1000049c0      bl sym.func.1000052a8
│           0x1000049c4      mov x22, x0
│           0x1000049c8      stur x0, [x29, -0x70]
│           0x1000049cc      adrp x0, segment.__DATA                   ; 0x100010000
│           0x1000049d0      add x0, x0, 0x338                         ; int64_t arg1
│           0x1000049d4      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x1000049d8      ldr x2, reloc.Foundation.ContiguousBytes.UInt8...szlMc ; 0x10000c338 ; int64_t arg3
│           0x1000049dc      mov x1, x21                               ; int64_t arg2
│           0x1000049e0      bl sym.func.1000053c8
│           0x1000049e4      stur x0, [x29, -0x68]
│           0x1000049e8      stur x20, [x29, -0x88]
│           0x1000049ec      sub x0, x29, 0x88                         ; int64_t arg1
│           0x1000049f0      mov x1, x22                               ; int64_t arg2
│           0x1000049f4      bl sym.func.10000532c
│           0x1000049f8      ldr x8, [x0]
│           0x1000049fc      add x0, x8, 0x20                          ; int64_t arg1
│           0x100004a00      ldr x8, [x8, 0x10]
│           0x100004a04      add x1, x0, x8                            ; int64_t arg2
│           0x100004a08      bl sym.func.1000047b8
│           0x100004a0c      mov x25, x0
│           0x100004a10      mov x28, x1
│           0x100004a14      sub x0, x29, 0x88                         ; int64_t arg1
│           0x100004a18      bl sym.func.100005350
│           0x100004a1c      adrp x0, segment.__DATA                   ; 0x100010000
│           0x100004a20      add x0, x0, 0x340                         ; int64_t arg1
│           0x100004a24      bl sym.func.1000052a8
│           0x100004a28      add x1, x19, 0x98                         ; void *arg1
│           0x100004a2c      bl sym.imp.swift_initStackObject          ; void *swift_initStackObject(void *arg0, void *arg1)
│           0x100004a30      mov x20, x0
│           0x100004a34      adrp x8, 0x100007000
│           0x100004a38      ldr q0, [x8, 0xad0]
│           0x100004a3c      str q0, [x0, 0x10]
│           0x100004a40      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004a44      ldr x8, reloc.kSecAttrKeyType             ; 0x10000c438
│           0x100004a48      ldr x0, [x8]
│           0x100004a4c      bl sym Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ ; sym.imp.Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ
│           0x100004a50      mov x21, x20
│           0x100004a54      str x0, [x21, 0x20]!
│           0x100004a58      str x1, [x20, 0x28]
│           0x100004a5c      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004a60      ldr x8, reloc.kSecAttrKeyTypeRSA          ; 0x10000c440
│           0x100004a64      ldr x23, [x8]
│           0x100004a68      mov x0, 0
│           0x100004a6c      bl sym.func.100005370
│           0x100004a70      mov x22, x0
│           0x100004a74      str x0, [x20, 0x48]
│           0x100004a78      str x23, [x20, 0x30]
│           0x100004a7c      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004a80      ldr x8, reloc.kSecAttrKeyClass            ; 0x10000c420
│           0x100004a84      ldr x0, [x8]
│           0x100004a88      bl sym Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ ; sym.imp.Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ
│           0x100004a8c      stp x0, x1, [x20, 0x50]
│           0x100004a90      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004a94      ldr x8, reloc.kSecAttrKeyClassPrivate     ; 0x10000c428
│           0x100004a98      ldr x27, [x8]
│           0x100004a9c      str x22, [x20, 0x78]
│           0x100004aa0      mov x22, x28
│           0x100004aa4      str x27, [x20, 0x60]
│           0x100004aa8      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004aac      ldr x8, reloc.kSecAttrKeySizeInBits       ; 0x10000c430
│           0x100004ab0      ldr x0, [x8]
│           0x100004ab4      bl sym Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ ; sym.imp.Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ
│           0x100004ab8      stp x0, x1, [x20, 0x80]
│           0x100004abc      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004ac0      ldr x8, reloc....SiN                      ; 0x10000c350
│           0x100004ac4      str x8, [x20, 0xa8]
│           0x100004ac8      mov w8, 0x400
│           0x100004acc      str x8, [x20, 0x90]
│           0x100004ad0      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004ad4      ldr x8, reloc.kSecReturnPersistentRef     ; 0x10000c450
│           0x100004ad8      ldr x0, [x8]
│           0x100004adc      bl sym Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ ; sym.imp.Foundation...nconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ
│           0x100004ae0      stp x0, x1, [x20, 0xb0]
│           0x100004ae4      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004ae8      ldr x8, reloc....SbN                      ; 0x10000c348
│           0x100004aec      str x8, [x20, 0xd8]
│           0x100004af0      mov w8, 1
│           0x100004af4      strb w8, [x20, 0xc0]
│           0x100004af8      bl sym.imp.objc_retain_x23
│           0x100004afc      mov x23, x25
│           0x100004b00      bl sym.imp.objc_retain_x27
│           0x100004b04      mov x0, x20                               ; int64_t arg1
│           0x100004b08      bl sym.func.100004820
│           0x100004b0c      mov x25, x0
│           0x100004b10      mov x0, x20
│           0x100004b14      bl sym.imp.swift_setDeallocating
│           0x100004b18      adrp x0, segment.__DATA                   ; 0x100010000
│           0x100004b1c      add x0, x0, 0x348                         ; int64_t arg1
│           0x100004b20      bl sym.func.1000052a8
│           0x100004b24      mov x2, x0
│           0x100004b28      mov x0, x21
│           0x100004b2c      mov w1, 4
│           0x100004b30      bl sym.imp.swift_arrayDestroy
│           0x100004b34      str xzr, [x19, 0x90]
│           0x100004b38      mov x0, x23
│           0x100004b3c      mov x1, x28
│           0x100004b40      bl sym Foundation.Data._bridgeToObjectiveC.NSData...F ; sym.imp.Foundation.Data._bridgeToObjectiveC.NSData...F
│           0x100004b44      mov x20, x0
│           0x100004b48      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004b4c      ldr x8, reloc....ypN                      ; 0x10000c3c8
│           0x100004b50      add x2, x8, 8
│           0x100004b54      adrp x1, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004b58      ldr x1, reloc....SSN                      ; 0x10000c320
│           0x100004b5c      adrp x3, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004b60      ldr x3, [x3, 0x328]
│           0x100004b64      mov x0, x25
│           0x100004b68      bl sym Foundationbool...ridgeToObjectiveCSo12NSDictionaryCyF ; sym.imp.Foundationbool...ridgeToObjectiveCSo12NSDictionaryCyF
│           0x100004b6c      mov x21, x0
│           0x100004b70      add x2, x19, 0x90
│           0x100004b74      mov x0, x20
│           0x100004b78      mov x1, x21
│           0x100004b7c      bl sym.imp.SecKeyCreateWithData
│           0x100004b80      mov x28, x0
│           0x100004b84      bl sym.imp.objc_release_x20
│           0x100004b88      bl sym.imp.objc_release_x21
│       ┌─< 0x100004b8c      cbz x28, 0x100004f68
│       │   0x100004b90      stp x26, x24, [x19, 0x60]
│       │   0x100004b94      mov x0, x28
│       │   0x100004b98      bl sym.imp.SecKeyCopyPublicKey
│      ┌──< 0x100004b9c      cbz x0, 0x100005028
│      ││   0x100004ba0      str x25, [x19, 0x38]
│      ││   0x100004ba4      mov x21, 0x10
│      ││   0x100004ba8      movk x21, 0xd000, lsl 48
│      ││   0x100004bac      add x1, x19, 0x90
│      ││   0x100004bb0      mov x26, x0
│      ││   0x100004bb4      bl sym.imp.SecKeyCopyExternalRepresentation
│      ││   0x100004bb8      ldp x24, x25, [x19, 0x68]
│      ││   0x100004bbc      ldr x27, [x19, 0x60]
│     ┌───< 0x100004bc0      cbz x0, 0x100005098
│     │││   0x100004bc4      mov x20, x0
│     │││   0x100004bc8      stp x22, x26, [x19, 0x28]
│     │││   0x100004bcc      str x23, [x19, 0x20]
│     │││   0x100004bd0      bl sym Foundation.Data._unconditionallyBridgeFromObjectiveC.NSData...gFZ ; sym.imp.Foundation.Data._unconditionallyBridgeFromObjectiveC.NSData...gFZ
│     │││   0x100004bd4      mov x26, x0
│     │││   0x100004bd8      mov x24, x1
│     │││   0x100004bdc      bl sym.imp.objc_release_x20
│     │││   0x100004be0      mov x0, x26                               ; int64_t arg1
│     │││   0x100004be4      mov x1, x24                               ; int64_t arg2
│     │││   0x100004be8      mov x25, 0x10
│     │││   0x100004bec      movk x25, 0xd000, lsl 48
│     │││   0x100004bf0      mov x21, 0
│     │││   0x100004bf4      bl sym.func.100004000
│     │││   0x100004bf8      mov x23, x0
│     │││   0x100004bfc      stur x0, [x29, -0x88]
│     │││   0x100004c00      adrp x20, segment.__DATA                  ; 0x100010000
│     │││   0x100004c04      add x20, x20, 0x360
│     │││   0x100004c08      mov x0, x20                               ; int64_t arg1
│     │││   0x100004c0c      bl sym.func.1000052a8
│     │││   0x100004c10      mov x27, x0
│     │││   0x100004c14      adrp x0, segment.__DATA                   ; 0x100010000
│     │││   0x100004c18      add x0, x0, 0x368                         ; int64_t arg1
│     │││   0x100004c1c      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│     │││   0x100004c20      ldr x2, reloc....SayxGSKsMc               ; 0x10000c340 ; int64_t arg3
│     │││   0x100004c24      mov x1, x20                               ; int64_t arg2
│     │││   0x100004c28      bl sym.func.1000053c8
│     │││   0x100004c2c      mov x22, x0
│     │││   0x100004c30      sub x20, x29, 0x88
│     │││   0x100004c34      mov x0, 0
│     │││   0x100004c38      mov x1, -0x2000000000000000
│     │││   0x100004c3c      str x27, [x19, 0x10]
│     │││   0x100004c40      mov x2, x27
│     │││   0x100004c44      mov x3, x22
│     │││   0x100004c48      bl sym Element...F                        ; sym.imp.Element...F
│     │││   0x100004c4c      str x0, [x19, 8]
│     │││   0x100004c50      str x1, [x19, 0x18]
│     │││   0x100004c54      mov x0, x23                               ; void *arg0
│     │││   0x100004c58      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│     │││   0x100004c5c      add x8, x25, 5
│     │││   0x100004c60      adrp x9, 0x100008000
│     │││   0x100004c64      add x9, x9, 0x540                         ; 0x100008540 ; "This is a sample text"
│     │││   0x100004c68      sub x9, x9, 0x20
│     │││   0x100004c6c      orr x9, x9, 0x8000000000000000
│     │││   0x100004c70      stp x8, x9, [x29, -0x88]
│     │││   0x100004c74      ldr x23, [x19, 0x58]
│     │││   0x100004c78      mov x8, x23
│     │││   0x100004c7c      bl sym Foundation...8EncodingV4utf8ACvgZ  ; sym.imp.Foundation...8EncodingV4utf8ACvgZ
│     │││   0x100004c80      bl sym.func.100005408
│     │││   0x100004c84      mov x3, x0
│     │││   0x100004c88      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│     │││   0x100004c8c      ldr x2, reloc....SSN                      ; 0x10000c320
│     │││   0x100004c90      sub x20, x29, 0x88
│     │││   0x100004c94      mov x0, x23
│     │││   0x100004c98      mov w1, 0
│     │││   0x100004c9c      bl sym Foundation...btF                   ; sym.imp.Foundation...btF
│     │││   0x100004ca0      str x0, [x19, 0x40]
│     │││   0x100004ca4      mov x20, x1
│     │││   0x100004ca8      ldp x8, x1, [x19, 0x48]
│     │││   0x100004cac      ldr x8, [x8, 8]
│     │││   0x100004cb0      mov x0, x23
│     │││   0x100004cb4      blr x8
│     │││   0x100004cb8      ldur x0, [x29, -0x80]                     ; void *arg0
│     │││   0x100004cbc      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│     │││   0x100004cc0      lsr x8, x20, 0x3c
│     │││   0x100004cc4      cmp x8, 0xe
│     │││   0x100004cc8      mov x25, 0x10
│     │││   0x100004ccc      movk x25, 0xd000, lsl 48
│    ┌────< 0x100004cd0      b.hi 0x100005280
│    ││││   0x100004cd4      adrp x8, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│    ││││   0x100004cd8      ldr x8, reloc.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256 ; 0x10000c448
│    ││││   0x100004cdc      ldr x23, [x8]
│    ││││   0x100004ce0      ldr x0, [x19, 0x40]
│    ││││   0x100004ce4      str x20, [x19, 0x50]
│    ││││   0x100004ce8      mov x1, x20
│    ││││   0x100004cec      bl sym Foundation.Data._bridgeToObjectiveC.NSData...F ; sym.imp.Foundation.Data._bridgeToObjectiveC.NSData...F
│    ││││   0x100004cf0      mov x20, x0
│    ││││   0x100004cf4      add x3, x19, 0x90
│    ││││   0x100004cf8      mov x0, x28
│    ││││   0x100004cfc      mov x1, x23
│    ││││   0x100004d00      mov x2, x20
│    ││││   0x100004d04      bl sym.imp.SecKeyCreateSignature
│    ││││   0x100004d08      mov x27, x0
│    ││││   0x100004d0c      bl sym.imp.objc_release_x20
│   ┌─────< 0x100004d10      cbz x27, 0x10000515c
│   │││││   0x100004d14      str x26, [x19]
│   │││││   0x100004d18      str x24, [x19, 0x48]
│   │││││   0x100004d1c      mov x0, x27
│   │││││   0x100004d20      bl sym Foundation.Data._unconditionallyBridgeFromObjectiveC.NSData...gFZ ; sym.imp.Foundation.Data._unconditionallyBridgeFromObjectiveC.NSData...gFZ
│   │││││   0x100004d24      mov x20, x0
│   │││││   0x100004d28      mov x26, x1
│   │││││   0x100004d2c      bl sym.func.100004000
│   │││││   0x100004d30      mov x21, x0
│   │││││   0x100004d34      mov x0, x20                               ; void *arg0
│   │││││   0x100004d38      mov x1, x26                               ; int64_t arg2
│   │││││   0x100004d3c      bl sym.func.100005384
│   │││││   0x100004d40      stur x21, [x29, -0x88]
│   │││││   0x100004d44      mov x24, -0x2000000000000000
│   │││││   0x100004d48      sub x20, x29, 0x88
│   │││││   0x100004d4c      mov x0, 0
│   │││││   0x100004d50      mov x1, -0x2000000000000000
│   │││││   0x100004d54      ldr x2, [x19, 0x10]
│   │││││   0x100004d58      mov x3, x22
│   │││││   0x100004d5c      bl sym Element...F                        ; sym.imp.Element...F
│   │││││   0x100004d60      str x0, [x19, 0x10]
│   │││││   0x100004d64      mov x26, x1
│   │││││   0x100004d68      mov x0, x21                               ; void *arg0
│   │││││   0x100004d6c      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│   │││││   0x100004d70      ldr x25, [x19, 0x40]
│   │││││   0x100004d74      mov x0, x25
│   │││││   0x100004d78      ldr x21, [x19, 0x50]
│   │││││   0x100004d7c      mov x1, x21
│   │││││   0x100004d80      bl sym Foundation.Data._bridgeToObjectiveC.NSData...F ; sym.imp.Foundation.Data._bridgeToObjectiveC.NSData...F
│   │││││   0x100004d84      mov x20, x0
│   │││││   0x100004d88      add x4, x19, 0x90
│   │││││   0x100004d8c      ldr x0, [x19, 0x30]
│   │││││   0x100004d90      mov x1, x23
│   │││││   0x100004d94      mov x2, x20
│   │││││   0x100004d98      mov x3, x27
│   │││││   0x100004d9c      bl sym.imp.SecKeyVerifySignature
│   │││││   0x100004da0      mov x23, x0
│   │││││   0x100004da4      bl sym.imp.objc_release_x20
│   │││││   0x100004da8      stp xzr, x24, [x29, -0x88]
│   │││││   0x100004dac      sub x20, x29, 0x88
│   │││││   0x100004db0      mov w0, 0x49                              ; 'I'
│   │││││   0x100004db4      bl sym _StringGuts.grow...SiF             ; sym.imp._StringGuts.grow...SiF
│   │││││   0x100004db8      ldp x8, x9, [x29, -0x88]
│   │││││   0x100004dbc      stp x8, x9, [x29, -0x88]
│   │││││   0x100004dc0      sub x20, x29, 0x88
│   │││││   0x100004dc4      mov x0, 0x724f                            ; 'Or'
│   │││││   0x100004dc8      movk x0, 0x6769, lsl 16                   ; 'ig'
│   │││││   0x100004dcc      movk x0, 0x6e69, lsl 32                   ; 'in'
│   │││││   0x100004dd0      movk x0, 0x6c61, lsl 48                   ; 'al'
│   │││││   0x100004dd4      mov x1, 0x203a                            ; ': '
│   │││││   0x100004dd8      movk x1, 0xea00, lsl 48
│   │││││   0x100004ddc      bl sym append...ySSF                      ; sym.imp.append...ySSF
│   │││││   0x100004de0      ldr x20, [x19, 0x58]
│   │││││   0x100004de4      mov x8, x20
│   │││││   0x100004de8      bl sym Foundation...8EncodingV4utf8ACvgZ  ; sym.imp.Foundation...8EncodingV4utf8ACvgZ
│   │││││   0x100004dec      mov x0, x25
│   │││││   0x100004df0      mov x1, x21
│   │││││   0x100004df4      mov x2, x20
│   │││││   0x100004df8      bl sym Foundation__String...AAE8EncodingVtcfC ; sym.imp.Foundation__String...AAE8EncodingVtcfC
│  ┌──────< 0x100004dfc      cbz x1, 0x100005294
│  ││││││   0x100004e00      mov x25, x1
│  ││││││   0x100004e04      adrp x8, 0x100008000
│  ││││││   0x100004e08      add x8, x8, 0x580                         ; 0x100008580 ; "Signature is valid."
│  ││││││   0x100004e0c      sub x8, x8, 0x20
│  ││││││   0x100004e10      orr x8, x8, 0x8000000000000000
│  ││││││   0x100004e14      adrp x9, 0x100008000
│  ││││││   0x100004e18      add x9, x9, 0x600                         ; 0x100008600 ; "Signature is invalid."
│  ││││││   0x100004e1c      sub x9, x9, 0x20
│  ││││││   0x100004e20      orr x9, x9, 0x8000000000000000
│  ││││││   0x100004e24      cmp w23, 0
│  ││││││   0x100004e28      csel x24, x9, x8, eq
│  ││││││   0x100004e2c      mov x22, 0x10
│  ││││││   0x100004e30      movk x22, 0xd000, lsl 48
│  ││││││   0x100004e34      add x21, x22, 3
│  ││││││   0x100004e38      add x8, x22, 5
│  ││││││   0x100004e3c      csel x23, x8, x21, eq
│  ││││││   0x100004e40      sub x20, x29, 0x88
│  ││││││   0x100004e44      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004e48      mov x0, x25                               ; void *arg0
│  ││││││   0x100004e4c      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  ││││││   0x100004e50      add x0, x22, 4
│  ││││││   0x100004e54      adrp x8, 0x100008000
│  ││││││   0x100004e58      add x8, x8, 0x5a0                         ; 0x1000085a0 ; "\n\nPublic Key (Hex): "
│  ││││││   0x100004e5c      sub x8, x8, 0x20
│  ││││││   0x100004e60      orr x1, x8, 0x8000000000000000
│  ││││││   0x100004e64      sub x20, x29, 0x88
│  ││││││   0x100004e68      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004e6c      sub x20, x29, 0x88
│  ││││││   0x100004e70      ldr x0, [x19, 8]
│  ││││││   0x100004e74      ldr x25, [x19, 0x18]
│  ││││││   0x100004e78      mov x1, x25
│  ││││││   0x100004e7c      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004e80      adrp x8, 0x100008000
│  ││││││   0x100004e84      add x8, x8, 0x5c0                         ; 0x1000085c0 ; "\n\nSignature (Hex): "
│  ││││││   0x100004e88      sub x8, x8, 0x20
│  ││││││   0x100004e8c      orr x1, x8, 0x8000000000000000
│  ││││││   0x100004e90      sub x20, x29, 0x88
│  ││││││   0x100004e94      mov x0, x21
│  ││││││   0x100004e98      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004e9c      sub x20, x29, 0x88
│  ││││││   0x100004ea0      ldr x0, [x19, 0x10]
│  ││││││   0x100004ea4      mov x1, x26
│  ││││││   0x100004ea8      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004eac      adrp x8, 0x100008000
│  ││││││   0x100004eb0      add x8, x8, 0x5e0                         ; 0x1000085e0 ; "\n\nVerification: "
│  ││││││   0x100004eb4      sub x8, x8, 0x20
│  ││││││   0x100004eb8      orr x1, x8, 0x8000000000000000
│  ││││││   0x100004ebc      sub x20, x29, 0x88
│  ││││││   0x100004ec0      mov x0, 0x10
│  ││││││   0x100004ec4      movk x0, 0xd000, lsl 48
│  ││││││   0x100004ec8      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004ecc      sub x20, x29, 0x88
│  ││││││   0x100004ed0      mov x0, x23
│  ││││││   0x100004ed4      mov x1, x24
│  ││││││   0x100004ed8      bl sym append...ySSF                      ; sym.imp.append...ySSF
│  ││││││   0x100004edc      ldp x8, x21, [x29, -0x88]
│  ││││││   0x100004ee0      ldr x10, [x19, 0x60]
│  ││││││   0x100004ee4      ldr x9, [x19, 0x68]
│  ││││││   0x100004ee8      stp x10, x9, [x29, -0x88]
│  ││││││   0x100004eec      ldr x9, [x19, 0x70]
│  ││││││   0x100004ef0      stur x9, [x29, -0x78]
│  ││││││   0x100004ef4      stp x8, x21, [x19, 0x80]
│  ││││││   0x100004ef8      mov x0, x21                               ; void *arg0
│  ││││││   0x100004efc      bl sym.imp.swift_bridgeObjectRetain       ; void *swift_bridgeObjectRetain(void *arg0)
│  ││││││   0x100004f00      adrp x0, segment.__DATA                   ; 0x100010000
│  ││││││   0x100004f04      add x0, x0, 0x358                         ; int64_t arg1
│  ││││││   0x100004f08      bl sym.func.1000052a8
│  ││││││   0x100004f0c      mov x1, x0
│  ││││││   0x100004f10      add x0, x19, 0x80
│  ││││││   0x100004f14      sub x20, x29, 0x88
│  ││││││   0x100004f18      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│  ││││││   0x100004f1c      ldr x0, [x19, 0x38]                       ; void *arg0
│  ││││││   0x100004f20      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  ││││││   0x100004f24      ldp x0, x1, [x19, 0x20]                   ; int64_t arg2
│  ││││││   0x100004f28      bl sym.func.100005384
│  ││││││   0x100004f2c      mov x0, x26                               ; void *arg0
│  ││││││   0x100004f30      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  ││││││   0x100004f34      mov x0, x24                               ; void *arg0
│  ││││││   0x100004f38      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  ││││││   0x100004f3c      mov x0, x21                               ; void *arg0
│  ││││││   0x100004f40      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  ││││││   0x100004f44      bl sym.imp.objc_release_x27
│  ││││││   0x100004f48      ldr x0, [x19, 0x40]                       ; int64_t arg2
│  ││││││   0x100004f4c      ldr x1, [x19, 0x50]
│  ││││││   0x100004f50      bl sym.func.10000544c
│  ││││││   0x100004f54      mov x0, x25                               ; void *arg0
│  ││││││   0x100004f58      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  ││││││   0x100004f5c      ldr x0, [x19]
│  ││││││   0x100004f60      ldr x1, [x19, 0x48]
│ ┌───────< 0x100004f64      b 0x100005234
│ │││││││   ; CODE XREF from sym.func.10000491c @ 0x100004b8c(x)
│ ││││││└─> 0x100004f68      mov x8, -0x2000000000000000
│ ││││││    0x100004f6c      stp xzr, x8, [x29, -0x88]
│ ││││││    0x100004f70      sub x20, x29, 0x88
│ ││││││    0x100004f74      mov w0, 0x20
│ ││││││    0x100004f78      bl sym _StringGuts.grow...SiF             ; sym.imp._StringGuts.grow...SiF
│ ││││││    0x100004f7c      ldur x0, [x29, -0x80]                     ; void *arg0
│ ││││││    0x100004f80      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││││    0x100004f84      mov x8, 0x10
│ ││││││    0x100004f88      movk x8, 0xd000, lsl 48
│ ││││││    0x100004f8c      orr x8, x8, 0xe
│ ││││││    0x100004f90      adrp x9, 0x100008000
│ ││││││    0x100004f94      add x9, x9, 0x4e0                         ; 0x1000084e0 ; "Failed to create private key: "
│ ││││││    0x100004f98      sub x9, x9, 0x20
│ ││││││    0x100004f9c      orr x9, x9, 0x8000000000000000
│ ││││││    0x100004fa0      stp x8, x9, [x29, -0x88]
│ ││││││    0x100004fa4      ldr x8, [x19, 0x90]
│ ││││││    0x100004fa8      str x8, [x19, 0x80]
│ ││││││    0x100004fac      adrp x0, segment.__DATA                   ; 0x100010000
│ ││││││    0x100004fb0      add x0, x0, 0x350                         ; int64_t arg1
│ ││││││    0x100004fb4      bl sym.func.1000052a8
│ ││││││    0x100004fb8      mov x1, x0
│ ││││││    0x100004fbc      add x0, x19, 0x80
│ ││││││    0x100004fc0      bl sym describing__String...clufC         ; sym.imp.describing__String...clufC
│ ││││││    0x100004fc4      mov x21, x1
│ ││││││    0x100004fc8      sub x20, x29, 0x88
│ ││││││    0x100004fcc      bl sym append...ySSF                      ; sym.imp.append...ySSF
│ ││││││    0x100004fd0      mov x0, x21                               ; void *arg0
│ ││││││    0x100004fd4      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││││    0x100004fd8      ldp x8, x21, [x29, -0x88]
│ ││││││    0x100004fdc      stp x26, x24, [x29, -0x88]
│ ││││││    0x100004fe0      ldr x9, [x19, 0x70]
│ ││││││    0x100004fe4      stur x9, [x29, -0x78]
│ ││││││    0x100004fe8      stp x8, x21, [x19, 0x80]
│ ││││││    0x100004fec      mov x0, x21                               ; void *arg0
│ ││││││    0x100004ff0      bl sym.imp.swift_bridgeObjectRetain       ; void *swift_bridgeObjectRetain(void *arg0)
│ ││││││    0x100004ff4      adrp x0, segment.__DATA                   ; 0x100010000
│ ││││││    0x100004ff8      add x0, x0, 0x358                         ; int64_t arg1
│ ││││││    0x100004ffc      bl sym.func.1000052a8
│ ││││││    0x100005000      mov x1, x0
│ ││││││    0x100005004      add x0, x19, 0x80
│ ││││││    0x100005008      sub x20, x29, 0x88
│ ││││││    0x10000500c      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│ ││││││    0x100005010      mov x0, x25                               ; void *arg0
│ ││││││    0x100005014      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││││    0x100005018      mov x0, x23                               ; void *arg0
│ ││││││    0x10000501c      mov x1, x22                               ; int64_t arg2
│ ││││││    0x100005020      bl sym.func.100005384
│ ││││││┌─< 0x100005024      b 0x100005150
│ │││││││   ; CODE XREF from sym.func.10000491c @ 0x100004b9c(x)
│ │││││└──> 0x100005028      ldr x9, [x19, 0x60]
│ │││││ │   0x10000502c      ldr x8, [x19, 0x68]
│ │││││ │   0x100005030      stp x9, x8, [x29, -0x88]
│ │││││ │   0x100005034      ldr x8, [x19, 0x70]
│ │││││ │   0x100005038      stur x8, [x29, -0x78]
│ │││││ │   0x10000503c      mov w8, 0xd
│ │││││ │   0x100005040      mov x9, 0x10
│ │││││ │   0x100005044      movk x9, 0xd000, lsl 48
│ │││││ │   0x100005048      orr x8, x9, x8
│ │││││ │   0x10000504c      adrp x9, 0x100008000
│ │││││ │   0x100005050      add x9, x9, 0x500                         ; 0x100008500 ; "Failed to generate public key"
│ │││││ │   0x100005054      sub x9, x9, 0x20
│ │││││ │   0x100005058      orr x9, x9, 0x8000000000000000
│ │││││ │   0x10000505c      stp x8, x9, [x19, 0x80]
│ │││││ │   0x100005060      adrp x0, segment.__DATA                   ; 0x100010000
│ │││││ │   0x100005064      add x0, x0, 0x358                         ; int64_t arg1
│ │││││ │   0x100005068      bl sym.func.1000052a8
│ │││││ │   0x10000506c      mov x1, x0
│ │││││ │   0x100005070      add x0, x19, 0x80
│ │││││ │   0x100005074      sub x20, x29, 0x88
│ │││││ │   0x100005078      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│ │││││ │   0x10000507c      mov x0, x25                               ; void *arg0
│ │││││ │   0x100005080      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ │││││ │   0x100005084      mov x0, x23                               ; void *arg0
│ │││││ │   0x100005088      mov x1, x22                               ; int64_t arg2
│ │││││ │   0x10000508c      bl sym.func.100005384
│ │││││ │   0x100005090      bl sym.imp.objc_release_x28
│ │││││┌──< 0x100005094      b 0x100005244
│ │││││││   ; CODE XREF from sym.func.10000491c @ 0x100004bc0(x)
│ ││││└───> 0x100005098      mov x8, -0x2000000000000000
│ ││││ ││   0x10000509c      stp xzr, x8, [x29, -0x88]
│ ││││ ││   0x1000050a0      sub x20, x29, 0x88
│ ││││ ││   0x1000050a4      mov w0, 0x20
│ ││││ ││   0x1000050a8      bl sym _StringGuts.grow...SiF             ; sym.imp._StringGuts.grow...SiF
│ ││││ ││   0x1000050ac      ldur x0, [x29, -0x80]                     ; void *arg0
│ ││││ ││   0x1000050b0      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││ ││   0x1000050b4      add x8, x21, 0xe
│ ││││ ││   0x1000050b8      adrp x9, 0x100008000
│ ││││ ││   0x1000050bc      add x9, x9, 0x520                         ; 0x100008520 ; "Failed to extract public key: "
│ ││││ ││   0x1000050c0      sub x9, x9, 0x20
│ ││││ ││   0x1000050c4      orr x9, x9, 0x8000000000000000
│ ││││ ││   0x1000050c8      stp x8, x9, [x29, -0x88]
│ ││││ ││   0x1000050cc      ldr x8, [x19, 0x90]
│ ││││ ││   0x1000050d0      str x8, [x19, 0x80]
│ ││││ ││   0x1000050d4      adrp x0, segment.__DATA                   ; 0x100010000
│ ││││ ││   0x1000050d8      add x0, x0, 0x350                         ; int64_t arg1
│ ││││ ││   0x1000050dc      bl sym.func.1000052a8
│ ││││ ││   0x1000050e0      mov x1, x0
│ ││││ ││   0x1000050e4      add x0, x19, 0x80
│ ││││ ││   0x1000050e8      bl sym describing__String...clufC         ; sym.imp.describing__String...clufC
│ ││││ ││   0x1000050ec      mov x21, x1
│ ││││ ││   0x1000050f0      sub x20, x29, 0x88
│ ││││ ││   0x1000050f4      bl sym append...ySSF                      ; sym.imp.append...ySSF
│ ││││ ││   0x1000050f8      mov x0, x21                               ; void *arg0
│ ││││ ││   0x1000050fc      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││ ││   0x100005100      ldp x8, x21, [x29, -0x88]
│ ││││ ││   0x100005104      stp x27, x24, [x29, -0x88]
│ ││││ ││   0x100005108      stur x25, [x29, -0x78]
│ ││││ ││   0x10000510c      stp x8, x21, [x19, 0x80]
│ ││││ ││   0x100005110      mov x0, x21                               ; void *arg0
│ ││││ ││   0x100005114      bl sym.imp.swift_bridgeObjectRetain       ; void *swift_bridgeObjectRetain(void *arg0)
│ ││││ ││   0x100005118      adrp x0, segment.__DATA                   ; 0x100010000
│ ││││ ││   0x10000511c      add x0, x0, 0x358                         ; int64_t arg1
│ ││││ ││   0x100005120      bl sym.func.1000052a8
│ ││││ ││   0x100005124      mov x1, x0
│ ││││ ││   0x100005128      add x0, x19, 0x80
│ ││││ ││   0x10000512c      sub x20, x29, 0x88
│ ││││ ││   0x100005130      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│ ││││ ││   0x100005134      ldr x0, [x19, 0x38]                       ; void *arg0
│ ││││ ││   0x100005138      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││ ││   0x10000513c      mov x0, x23                               ; void *arg0
│ ││││ ││   0x100005140      mov x1, x22                               ; int64_t arg2
│ ││││ ││   0x100005144      bl sym.func.100005384
│ ││││ ││   0x100005148      bl sym.imp.objc_release_x28
│ ││││ ││   0x10000514c      bl sym.imp.objc_release_x26
│ ││││ ││   ; CODE XREF from sym.func.10000491c @ 0x100005024(x)
│ ││││ │└─> 0x100005150      mov x0, x21                               ; void *arg0
│ ││││ │    0x100005154      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││││ │┌─< 0x100005158      b 0x100005244
│ ││││ ││   ; CODE XREF from sym.func.10000491c @ 0x100004d10(x)
│ ││└─────> 0x10000515c      mov x8, -0x2000000000000000
│ ││ │ ││   0x100005160      stp xzr, x8, [x29, -0x88]
│ ││ │ ││   0x100005164      sub x20, x29, 0x88
│ ││ │ ││   0x100005168      mov w0, 0x12
│ ││ │ ││   0x10000516c      bl sym _StringGuts.grow...SiF             ; sym.imp._StringGuts.grow...SiF
│ ││ │ ││   0x100005170      ldur x0, [x29, -0x80]                     ; void *arg0
│ ││ │ ││   0x100005174      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││ │ ││   0x100005178      adrp x8, 0x100008000
│ ││ │ ││   0x10000517c      add x8, x8, 0x560                         ; 0x100008560 ; "Signing failed: "
│ ││ │ ││   0x100005180      sub x8, x8, 0x20
│ ││ │ ││   0x100005184      orr x8, x8, 0x8000000000000000
│ ││ │ ││   0x100005188      stp x25, x8, [x29, -0x88]
│ ││ │ ││   0x10000518c      ldr x8, [x19, 0x90]
│ ││ │ ││   0x100005190      str x8, [x19, 0x80]
│ ││ │ ││   0x100005194      adrp x0, segment.__DATA                   ; 0x100010000
│ ││ │ ││   0x100005198      add x0, x0, 0x350                         ; int64_t arg1
│ ││ │ ││   0x10000519c      bl sym.func.1000052a8
│ ││ │ ││   0x1000051a0      mov x1, x0
│ ││ │ ││   0x1000051a4      add x0, x19, 0x80
│ ││ │ ││   0x1000051a8      bl sym describing__String...clufC         ; sym.imp.describing__String...clufC
│ ││ │ ││   0x1000051ac      mov x21, x1
│ ││ │ ││   0x1000051b0      sub x20, x29, 0x88
│ ││ │ ││   0x1000051b4      bl sym append...ySSF                      ; sym.imp.append...ySSF
│ ││ │ ││   0x1000051b8      mov x0, x21                               ; void *arg0
│ ││ │ ││   0x1000051bc      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││ │ ││   0x1000051c0      ldp x8, x21, [x29, -0x88]
│ ││ │ ││   0x1000051c4      ldr x10, [x19, 0x60]
│ ││ │ ││   0x1000051c8      ldr x9, [x19, 0x68]
│ ││ │ ││   0x1000051cc      stp x10, x9, [x29, -0x88]
│ ││ │ ││   0x1000051d0      ldr x9, [x19, 0x70]
│ ││ │ ││   0x1000051d4      stur x9, [x29, -0x78]
│ ││ │ ││   0x1000051d8      stp x8, x21, [x19, 0x80]
│ ││ │ ││   0x1000051dc      mov x0, x21                               ; void *arg0
│ ││ │ ││   0x1000051e0      bl sym.imp.swift_bridgeObjectRetain       ; void *swift_bridgeObjectRetain(void *arg0)
│ ││ │ ││   0x1000051e4      adrp x0, segment.__DATA                   ; 0x100010000
│ ││ │ ││   0x1000051e8      add x0, x0, 0x358                         ; int64_t arg1
│ ││ │ ││   0x1000051ec      bl sym.func.1000052a8
│ ││ │ ││   0x1000051f0      mov x1, x0
│ ││ │ ││   0x1000051f4      add x0, x19, 0x80
│ ││ │ ││   0x1000051f8      sub x20, x29, 0x88
│ ││ │ ││   0x1000051fc      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│ ││ │ ││   0x100005200      ldr x0, [x19, 0x38]                       ; void *arg0
│ ││ │ ││   0x100005204      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││ │ ││   0x100005208      ldp x0, x1, [x19, 0x20]                   ; int64_t arg2
│ ││ │ ││   0x10000520c      bl sym.func.100005384
│ ││ │ ││   0x100005210      mov x0, x21                               ; void *arg0
│ ││ │ ││   0x100005214      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││ │ ││   0x100005218      ldr x0, [x19, 0x40]                       ; int64_t arg2
│ ││ │ ││   0x10000521c      ldr x1, [x19, 0x50]
│ ││ │ ││   0x100005220      bl sym.func.10000544c
│ ││ │ ││   0x100005224      ldr x0, [x19, 0x18]                       ; void *arg0
│ ││ │ ││   0x100005228      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│ ││ │ ││   0x10000522c      mov x0, x26
│ ││ │ ││   0x100005230      mov x1, x24
│ ││ │ ││   ; CODE XREF from sym.func.10000491c @ 0x100004f64(x)
│ └───────> 0x100005234      bl sym.func.100005384
│  │ │ ││   0x100005238      bl sym.imp.objc_release_x28
│  │ │ ││   0x10000523c      ldr x8, [x19, 0x30]
│  │ │ ││   0x100005240      bl sym.imp.objc_release_x8
│  │ │ ││   ; CODE XREFS from sym.func.10000491c @ 0x100005094(x), 0x100005158(x)
│  │ │ └└─> 0x100005244      ldur x8, [x29, -0x60]
│  │ │      0x100005248      adrp x9, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│  │ │      0x10000524c      ldr x9, reloc.__stack_chk_guard           ; 0x10000c408
│  │ │      0x100005250      ldr x9, [x9]
│  │ │      0x100005254      cmp x9, x8
│  │ │  ┌─< 0x100005258      b.ne 0x10000527c
│  │ │  │   0x10000525c      sub sp, x29, 0x50
│  │ │  │   0x100005260      ldp x29, x30, [var_50h_2]
│  │ │  │   0x100005264      ldp x20, x19, [var_40h]
│  │ │  │   0x100005268      ldp x22, x21, [var_30h]
│  │ │  │   0x10000526c      ldp x24, x23, [var_20h]
│  │ │  │   0x100005270      ldp x26, x25, [var_10h]
│  │ │  │   0x100005274      ldp x28, x27, [sp], 0x60
│  │ │  │   0x100005278      ret
│  │ │  │   ; CODE XREF from sym.func.10000491c @ 0x100005258(x)
│  │ │  └─> 0x10000527c      bl sym.imp.__stack_chk_fail               ; void __stack_chk_fail(void)
│  │ │      ; CODE XREF from sym.func.10000491c @ 0x100004cd0(x)
│  │ └────> 0x100005280      ldr x0, [x19, 0x68]                       ; void *arg0
│  │        0x100005284      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│  │        0x100005288      ldr x0, [x19, 0x70]                       ; void *arg0
│  │        0x10000528c      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
│  │        0x100005290      brk 1
│  │        ; CODE XREF from sym.func.10000491c @ 0x100004dfc(x)
│  └──────> 0x100005294      ldr x0, [x19, 0x68]                       ; void *arg0
│           0x100005298      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│           0x10000529c      ldr x0, [x19, 0x70]                       ; void *arg0
│           0x1000052a0      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
└           0x1000052a4      brk 1
