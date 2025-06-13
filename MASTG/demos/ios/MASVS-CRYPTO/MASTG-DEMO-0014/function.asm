            ; CALL XREF from sym.func.100005f30 @ 0x100005f68(x)
┌ 1840: sym.func.1000046dc (int64_t arg1, int64_t arg2, int64_t arg3);
│           0x1000046dc      stp x28, x27, [sp, -0x60]!
│           0x1000046e0      stp x26, x25, [var_10h]
│           0x1000046e4      stp x24, x23, [var_20h]
│           0x1000046e8      stp x22, x21, [var_30h]
│           0x1000046ec      stp x20, x19, [var_40h]
│           0x1000046f0      stp x29, x30, [var_50h_2]
│           0x1000046f4      add x29, sp, 0x50
│           0x1000046f8      sub sp, sp, 0xe0
│           0x1000046fc      stp x1, x2, [x29, -0xa8]                  ; arg3
│           0x100004700      stur x0, [x29, -0xb0]                     ; arg1
│           0x100004704      mov x0, 0
│           0x100004708      bl sym CryptoKit.P256.Signing.ECDSASignature...VMa ; sym.imp.CryptoKit.P256.Signing.ECDSASignature...VMa
│           0x10000470c      ldur x8, [x0, -8]
│           0x100004710      stp x8, x0, [x29, -0xe0]
│           0x100004714      ldr x8, [x8, 0x40]
│           0x100004718      mov x9, x8
│           0x10000471c      adrp x16, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004720      ldr x16, reloc.__chkstk_darwin            ; 0x10000c3b8
│           0x100004724      blr x16
│           0x100004728      mov x9, sp
│           0x10000472c      add x8, x8, 0xf
│           0x100004730      and x8, x8, 0xfffffffffffffff0
│           0x100004734      sub x8, x9, x8
│           0x100004738      stur x8, [x29, -0xb8]
│           0x10000473c      mov sp, x8
│           0x100004740      mov x0, 0
│           0x100004744      bl sym Foundation...8EncodingVMa          ; sym.imp.Foundation...8EncodingVMa
│           0x100004748      ldur x8, [x0, -8]
│           0x10000474c      stp x8, x0, [x29, -0xd0]
│           0x100004750      ldr x8, [x8, 0x40]
│           0x100004754      mov x9, x8
│           0x100004758      adrp x16, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x10000475c      ldr x16, reloc.__chkstk_darwin            ; 0x10000c3b8
│           0x100004760      blr x16
│           0x100004764      mov x9, sp
│           0x100004768      add x8, x8, 0xf
│           0x10000476c      and x8, x8, 0xfffffffffffffff0
│           0x100004770      sub x8, x9, x8
│           0x100004774      stur x8, [x29, -0xc0]
│           0x100004778      mov sp, x8
│           0x10000477c      mov x0, 0
│           0x100004780      bl sym CryptoKit.P256.Signing.PublicKey...VMa ; sym.imp.CryptoKit.P256.Signing.PublicKey...VMa
│           0x100004784      mov x27, x0
│           0x100004788      ldur x26, [x0, -8]
│           0x10000478c      ldr x8, [x26, 0x40]
│           0x100004790      mov x9, x8
│           0x100004794      adrp x16, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004798      ldr x16, reloc.__chkstk_darwin            ; 0x10000c3b8
│           0x10000479c      blr x16
│           0x1000047a0      mov x9, sp
│           0x1000047a4      add x8, x8, 0xf
│           0x1000047a8      and x8, x8, 0xfffffffffffffff0
│           0x1000047ac      sub x25, x9, x8
│           0x1000047b0      mov sp, x25
│           0x1000047b4      adrp x0, segment.__DATA                   ; 0x100010000
│           0x1000047b8      add x0, x0, 0xe8                          ; int64_t arg1
│           0x1000047bc      bl sym.func.100004e0c
│           0x1000047c0      ldur x8, [x0, -8]
│           0x1000047c4      ldr x8, [x8, 0x40]
│           0x1000047c8      mov x9, x8
│           0x1000047cc      adrp x16, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x1000047d0      ldr x16, reloc.__chkstk_darwin            ; 0x10000c3b8
│           0x1000047d4      blr x16
│           0x1000047d8      mov x9, sp
│           0x1000047dc      add x8, x8, 0xf
│           0x1000047e0      and x8, x8, 0xfffffffffffffff0
│           0x1000047e4      sub x20, x9, x8
│           0x1000047e8      mov sp, x20
│           0x1000047ec      mov x0, 0
│           0x1000047f0      bl sym CryptoKit.P256.Signing.PrivateKey...VMa ; sym.imp.CryptoKit.P256.Signing.PrivateKey...VMa
│           0x1000047f4      mov x23, x0
│           0x1000047f8      ldur x28, [x0, -8]
│           0x1000047fc      ldr x8, [x28, 0x40]
│           0x100004800      mov x9, x8
│           0x100004804      adrp x16, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004808      ldr x16, reloc.__chkstk_darwin            ; 0x10000c3b8
│           0x10000480c      blr x16
│           0x100004810      mov x9, sp
│           0x100004814      add x8, x8, 0xf
│           0x100004818      and x8, x8, 0xfffffffffffffff0
│           0x10000481c      sub x24, x9, x8
│           0x100004820      mov sp, x24
│           0x100004824      adrp x0, segment.__DATA                   ; 0x100010000
│           0x100004828      add x0, x0, 0xf0                          ; int64_t arg1
│           0x10000482c      bl sym.func.100004e0c
│           0x100004830      adrp x1, segment.__DATA                   ; 0x100010000
│           0x100004834      add x1, x1, 0xa8
│           0x100004838      bl sym.imp.swift_initStaticObject
│           0x10000483c      mov x19, x0
│           0x100004840      adrp x21, segment.__DATA                  ; 0x100010000
│           0x100004844      add x21, x21, 0xf8
│           0x100004848      mov x0, x21                               ; int64_t arg1
│           0x10000484c      bl sym.func.100004e0c
│           0x100004850      mov x22, x0
│           0x100004854      stur x0, [x29, -0x68]
│           0x100004858      adrp x0, segment.__DATA                   ; 0x100010000
│           0x10000485c      add x0, x0, 0x100                         ; int64_t arg1
│           0x100004860      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x100004864      ldr x2, reloc.Foundation.ContiguousBytes.UInt8...szlMc ; 0x10000c368 ; int64_t arg3
│           0x100004868      mov x1, x21                               ; int64_t arg2
│           0x10000486c      bl sym.func.100005024
│           0x100004870      stur x0, [x29, -0x60]
│           0x100004874      stur x19, [x29, -0x80]
│           0x100004878      sub x0, x29, 0x80                         ; int64_t arg1
│           0x10000487c      mov x1, x22                               ; int64_t arg2
│           0x100004880      bl sym.func.100004e90
│           0x100004884      ldr x8, [x0]
│           0x100004888      add x0, x8, 0x20                          ; int64_t arg1
│           0x10000488c      ldr x8, [x8, 0x10]
│           0x100004890      add x1, x0, x8                            ; int64_t arg2
│           0x100004894      bl sym.func.100004674
│           0x100004898      mov x22, x0
│           0x10000489c      mov x19, x1
│           0x1000048a0      sub x0, x29, 0x80                         ; int64_t arg1
│           0x1000048a4      bl sym.func.100004eb4
│           0x1000048a8      stp x22, x19, [x29, -0x80]
│           0x1000048ac      mov x0, x22                               ; int64_t arg2
│           0x1000048b0      mov x1, x19
│           0x1000048b4      bl sym.func.100004ed4
│           0x1000048b8      adrp x1, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x1000048bc      ldr x1, [x1, 0x38]                        ; 0x10000c038
│                                                                      ; reloc.Foundation.Data...VN
│           0x1000048c0      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│           0x1000048c4      ldr x2, [x2, 0x30]                        ; 0x10000c030
│                                                                      ; reloc.Foundation.Data...VAA15ContiguousBytesAAWP.ContiguousBytes...WP
│           0x1000048c8      sub x0, x29, 0x80
│           0x1000048cc      mov x8, x20
│           0x1000048d0      mov x21, 0
│           0x1000048d4      bl sym CryptoKit.P256.Signing.PrivateKey.rawRepresentation.Foundation.ContiguousBytes...lufC ; sym.imp.CryptoKit.P256.Signing.PrivateKey.rawRepresentation.Foundation.ContiguousBytes...lufC
│       ┌─< 0x1000048d8      cbz x21, 0x100004900
│       │   0x1000048dc      mov x0, x21
│       │   0x1000048e0      bl sym.imp.swift_errorRelease
│       │   0x1000048e4      ldr x8, [x28, 0x38]
│       │   0x1000048e8      mov x0, x20
│       │   0x1000048ec      mov w1, 1
│       │   0x1000048f0      mov w2, 1
│       │   0x1000048f4      mov x3, x23
│       │   0x1000048f8      blr x8
│      ┌──< 0x1000048fc      b 0x100004940
│      ││   ; CODE XREF from sym.func.1000046dc @ 0x1000048d8(x)
│      │└─> 0x100004900      stp x27, x24, [x29, -0xf0]
│      │    0x100004904      stur x26, [x29, -0xf8]
│      │    0x100004908      ldur x27, [x29, -0xb8]
│      │    0x10000490c      ldr x8, [x28, 0x38]
│      │    0x100004910      mov x0, x20
│      │    0x100004914      mov w1, 0
│      │    0x100004918      mov w2, 1
│      │    0x10000491c      mov x3, x23
│      │    0x100004920      blr x8
│      │    0x100004924      ldr x8, [x28, 0x30]
│      │    0x100004928      mov x0, x20
│      │    0x10000492c      mov w1, 1
│      │    0x100004930      mov x2, x23
│      │    0x100004934      blr x8
│      │    0x100004938      cmp w0, 1
│      │┌─< 0x10000493c      b.ne 0x1000049c4
│      ││   ; CODE XREF from sym.func.1000046dc @ 0x1000048fc(x)
│      └──> 0x100004940      mov x0, x20                               ; int64_t arg1
│       │   0x100004944      bl sym.func.100004f18
│       │   0x100004948      ldur x9, [x29, -0xb0]
│       │   0x10000494c      ldur x8, [x29, -0xa8]
│       │   0x100004950      stp x9, x8, [x29, -0x80]
│       │   0x100004954      ldur x8, [x29, -0xa0]
│       │   0x100004958      stur x8, [x29, -0x70]
│       │   0x10000495c      mov x8, 0x13
│       │   0x100004960      movk x8, 0xd000, lsl 48
│       │   0x100004964      add x8, x8, 0xa
│       │   0x100004968      adrp x9, 0x100007000
│       │   0x10000496c      add x9, x9, 0xf00                         ; 0x100007f00 ; "Failed to create private key."
│       │   0x100004970      sub x9, x9, 0x20
│       │   0x100004974      orr x9, x9, 0x8000000000000000
│       │   0x100004978      stp x8, x9, [x29, -0x98]
│       │   0x10000497c      adrp x0, segment.__DATA                   ; 0x100010000
│       │   0x100004980      add x0, x0, 0x108                         ; int64_t arg1
│       │   0x100004984      bl sym.func.100004e0c
│       │   0x100004988      mov x1, x0
│       │   0x10000498c      sub x0, x29, 0x98
│       │   0x100004990      sub x20, x29, 0x80
│       │   0x100004994      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│       │   ; CODE XREF from sym.func.1000046dc @ 0x100004db0(x)
│      ┌──> 0x100004998      mov x0, x22                               ; void *arg0
│      ╎│   0x10000499c      mov x1, x19                               ; int64_t arg2
│      ╎│   0x1000049a0      bl sym.func.100004f58
│      ╎│   0x1000049a4      sub sp, x29, 0x50
│      ╎│   0x1000049a8      ldp x29, x30, [var_50h_2]
│      ╎│   0x1000049ac      ldp x20, x19, [var_40h]
│      ╎│   0x1000049b0      ldp x22, x21, [var_30h]
│      ╎│   0x1000049b4      ldp x24, x23, [var_20h]
│      ╎│   0x1000049b8      ldp x26, x25, [var_10h]
│      ╎│   0x1000049bc      ldp x28, x27, [sp], 0x60
│      ╎│   0x1000049c0      ret
│      ╎│   ; CODE XREF from sym.func.1000046dc @ 0x10000493c(x)
│      ╎└─> 0x1000049c4      ldr x8, [x28, 0x20]
│      ╎    0x1000049c8      ldur x26, [x29, -0xe8]
│      ╎    0x1000049cc      mov x0, x26
│      ╎    0x1000049d0      mov x1, x20
│      ╎    0x1000049d4      mov x2, x23
│      ╎    0x1000049d8      blr x8
│      ╎    0x1000049dc      stur x25, [x29, -0x100]
│      ╎    0x1000049e0      mov x8, x25
│      ╎    0x1000049e4      mov x20, x26
│      ╎    0x1000049e8      bl sym CryptoKit.P256.Signing.PrivateKey.public...F0AE06PublicF0Vvg.Public...F0Vvg...Vvg ; sym.imp.CryptoKit.P256.Signing.PrivateKey.public...F0AE06PublicF0Vvg.Public...F0Vvg...Vvg
│      ╎    0x1000049ec      mov x8, 0x13
│      ╎    0x1000049f0      movk x8, 0xd000, lsl 48
│      ╎    0x1000049f4      add x8, x8, 2
│      ╎    0x1000049f8      adrp x9, 0x100007000
│      ╎    0x1000049fc      add x9, x9, 0xf20                         ; 0x100007f20 ; "This is a sample text"
│      ╎    0x100004a00      sub x9, x9, 0x20
│      ╎    0x100004a04      orr x9, x9, 0x8000000000000000
│      ╎    0x100004a08      stp x8, x9, [x29, -0x80]
│      ╎    0x100004a0c      ldur x25, [x29, -0xc0]
│      ╎    0x100004a10      mov x8, x25
│      ╎    0x100004a14      bl sym Foundation...8EncodingV4utf8ACvgZ  ; sym.imp.Foundation...8EncodingV4utf8ACvgZ
│      ╎    0x100004a18      bl sym.func.100004f9c
│      ╎    0x100004a1c      mov x3, x0
│      ╎    0x100004a20      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│      ╎    0x100004a24      ldr x2, reloc....SSN                      ; 0x10000c358
│      ╎    0x100004a28      sub x20, x29, 0x80
│      ╎    0x100004a2c      mov x0, x25
│      ╎    0x100004a30      mov w1, 0
│      ╎    0x100004a34      bl sym Foundation...btF                   ; sym.imp.Foundation...btF
│      ╎    0x100004a38      mov x20, x0
│      ╎    0x100004a3c      mov x24, x1
│      ╎    0x100004a40      ldp x8, x1, [x29, -0xd0]
│      ╎    0x100004a44      ldr x8, [x8, 8]
│      ╎    0x100004a48      mov x0, x25
│      ╎    0x100004a4c      blr x8
│      ╎    0x100004a50      ldur x0, [x29, -0x78]                     ; void *arg0
│      ╎    0x100004a54      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│      ╎    0x100004a58      stur x24, [x29, -0xc8]
│      ╎    0x100004a5c      lsr x8, x24, 0x3c
│      ╎    0x100004a60      cmp x8, 0xe
│      ╎┌─< 0x100004a64      b.hi 0x100004db4
│      ╎│   0x100004a68      sub x8, x29, 0x10
│      ╎│   0x100004a6c      stur x28, [x8, -0x100]
│      ╎│   0x100004a70      sub x8, x29, 8
│      ╎│   0x100004a74      stur x23, [x8, -0x100]
│      ╎│   0x100004a78      stur x20, [x29, -0xd0]
│      ╎│   0x100004a7c      ldur x8, [x29, -0xc8]
│      ╎│   0x100004a80      stp x20, x8, [x29, -0x80]
│      ╎│   0x100004a84      bl sym.func.100004fe0
│      ╎│   0x100004a88      mov x2, x0
│      ╎│   0x100004a8c      adrp x1, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│      ╎│   0x100004a90      ldr x1, [x1, 0x38]                        ; 0x10000c038
│      ╎│                                                              ; reloc.Foundation.Data...VN
│      ╎│   0x100004a94      sub x0, x29, 0x80
│      ╎│   0x100004a98      mov x28, x27
│      ╎│   0x100004a9c      mov x27, x2
│      ╎│   0x100004aa0      mov x8, x28
│      ╎│   0x100004aa4      mov x20, x26
│      ╎│   0x100004aa8      bl sym CryptoKit.P256.Signing.PrivateKey.signature.for.ECDSASignature.Foundation.DataProtocol...lF ; sym.imp.CryptoKit.P256.Signing.PrivateKey.signature.for.ECDSASignature.Foundation.DataProtocol...lF
│     ┌───< 0x100004aac      cbnz x21, 0x100004ddc
│     │╎│   0x100004ab0      mov x20, x28
│     │╎│   0x100004ab4      bl sym CryptoKit.P256.Signing.ECDSASignature.rawRepresentation.Foundation.Data...Vvg ; sym.imp.CryptoKit.P256.Signing.ECDSASignature.rawRepresentation.Foundation.Data...Vvg
│     │╎│   0x100004ab8      mov x20, x0
│     │╎│   0x100004abc      mov x25, x1
│     │╎│   0x100004ac0      bl sym.func.100004000
│     │╎│   0x100004ac4      mov x26, x0
│     │╎│   0x100004ac8      mov x0, x20                               ; void *arg0
│     │╎│   0x100004acc      mov x1, x25                               ; int64_t arg2
│     │╎│   0x100004ad0      bl sym.func.100004f58
│     │╎│   0x100004ad4      stur x26, [x29, -0x80]
│     │╎│   0x100004ad8      adrp x20, segment.__DATA                  ; 0x100010000
│     │╎│   0x100004adc      add x20, x20, 0x120
│     │╎│   0x100004ae0      mov x0, x20                               ; int64_t arg1
│     │╎│   0x100004ae4      bl sym.func.100004e0c
│     │╎│   0x100004ae8      mov x23, x0
│     │╎│   0x100004aec      adrp x0, segment.__DATA                   ; 0x100010000
│     │╎│   0x100004af0      add x0, x0, 0x128                         ; int64_t arg1
│     │╎│   0x100004af4      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│     │╎│   0x100004af8      ldr x2, reloc....SayxGSKsMc               ; 0x10000c370 ; int64_t arg3
│     │╎│   0x100004afc      mov x1, x20                               ; int64_t arg2
│     │╎│   0x100004b00      bl sym.func.100005024
│     │╎│   0x100004b04      mov x3, x0
│     │╎│   0x100004b08      mov x25, -0x2000000000000000
│     │╎│   0x100004b0c      sub x20, x29, 0x80
│     │╎│   0x100004b10      mov x0, 0
│     │╎│   0x100004b14      mov x1, -0x2000000000000000
│     │╎│   0x100004b18      sub x8, x29, 0x28
│     │╎│   0x100004b1c      stur x23, [x8, -0x100]
│     │╎│   0x100004b20      mov x2, x23
│     │╎│   0x100004b24      sub x8, x29, 0x30
│     │╎│   0x100004b28      stur x3, [x8, -0x100]
│     │╎│   0x100004b2c      bl sym Element...F                        ; sym.imp.Element...F
│     │╎│   0x100004b30      sub x8, x29, 0x20
│     │╎│   0x100004b34      stur x0, [x8, -0x100]
│     │╎│   0x100004b38      sub x8, x29, 0x18
│     │╎│   0x100004b3c      stur x1, [x8, -0x100]
│     │╎│   0x100004b40      mov x0, x26                               ; void *arg0
│     │╎│   0x100004b44      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│     │╎│   0x100004b48      ldp x23, x24, [x29, -0xd0]
│     │╎│   0x100004b4c      stp x23, x24, [x29, -0x80]
│     │╎│   0x100004b50      adrp x2, reloc.Foundation.__DataStorage.bytes.allocator...itcfc ; 0x10000c000
│     │╎│   0x100004b54      ldr x2, [x2, 0x38]                        ; 0x10000c038
│     │╎│                                                              ; reloc.Foundation.Data...VN
│     │╎│   0x100004b58      sub x1, x29, 0x80
│     │╎│   0x100004b5c      mov x0, x28
│     │╎│   0x100004b60      mov x3, x27
│     │╎│   0x100004b64      ldur x27, [x29, -0x100]
│     │╎│   0x100004b68      mov x20, x27
│     │╎│   0x100004b6c      bl sym CryptoKit.P256.Signing.PublicKey.isValidSignature.for.ECDSASignature.Foundation.DataProtocol...lF ; sym.imp.CryptoKit.P256.Signing.PublicKey.isValidSignature.for.ECDSASignature.Foundation.DataProtocol...lF
│     │╎│   0x100004b70      mov x26, x0
│     │╎│   0x100004b74      stp xzr, x25, [x29, -0x80]
│     │╎│   0x100004b78      sub x20, x29, 0x80
│     │╎│   0x100004b7c      mov w0, 0x49                              ; 'I'
│     │╎│   0x100004b80      bl sym _StringGuts.grow...SiF             ; sym.imp._StringGuts.grow...SiF
│     │╎│   0x100004b84      ldp x8, x9, [x29, -0x80]
│     │╎│   0x100004b88      stp x8, x9, [x29, -0x80]
│     │╎│   0x100004b8c      sub x20, x29, 0x80
│     │╎│   0x100004b90      mov x0, 0x724f                            ; 'Or'
│     │╎│   0x100004b94      movk x0, 0x6769, lsl 16                   ; 'ig'
│     │╎│   0x100004b98      movk x0, 0x6e69, lsl 32                   ; 'in'
│     │╎│   0x100004b9c      movk x0, 0x6c61, lsl 48                   ; 'al'
│     │╎│   0x100004ba0      mov x1, 0x203a                            ; ': '
│     │╎│   0x100004ba4      movk x1, 0xea00, lsl 48
│     │╎│   0x100004ba8      bl sym append...ySSF                      ; sym.imp.append...ySSF
│     │╎│   0x100004bac      ldur x20, [x29, -0xc0]
│     │╎│   0x100004bb0      mov x8, x20
│     │╎│   0x100004bb4      bl sym Foundation...8EncodingV4utf8ACvgZ  ; sym.imp.Foundation...8EncodingV4utf8ACvgZ
│     │╎│   0x100004bb8      mov x0, x23
│     │╎│   0x100004bbc      mov x1, x24
│     │╎│   0x100004bc0      mov x2, x20
│     │╎│   0x100004bc4      bl sym Foundation__String...AAE8EncodingVtcfC ; sym.imp.Foundation__String...AAE8EncodingVtcfC
│    ┌────< 0x100004bc8      cbz x1, 0x100004dc8
│    ││╎│   0x100004bcc      mov x23, x27
│    ││╎│   0x100004bd0      mov x24, x1
│    ││╎│   0x100004bd4      adrp x8, 0x100007000
│    ││╎│   0x100004bd8      add x8, x8, 0xf60                         ; 0x100007f60 ; "Signature is invalid."
│    ││╎│   0x100004bdc      sub x8, x8, 0x20
│    ││╎│   0x100004be0      orr x8, x8, 0x8000000000000000
│    ││╎│   0x100004be4      adrp x9, 0x100007000
│    ││╎│   0x100004be8      add x9, x9, 0xfe0                         ; 0x100007fe0 ; "Signature is valid."
│    ││╎│   0x100004bec      sub x9, x9, 0x20
│    ││╎│   0x100004bf0      orr x9, x9, 0x8000000000000000
│    ││╎│   0x100004bf4      tst w26, 1
│    ││╎│   0x100004bf8      csel x26, x9, x8, ne
│    ││╎│   0x100004bfc      mov x27, 0x13
│    ││╎│   0x100004c00      movk x27, 0xd000, lsl 48
│    ││╎│   0x100004c04      add x8, x27, 2
│    ││╎│   0x100004c08      csel x8, x27, x8, ne
│    ││╎│   0x100004c0c      stur x8, [x29, -0xc0]
│    ││╎│   0x100004c10      sub x20, x29, 0x80
│    ││╎│   0x100004c14      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004c18      mov x0, x24                               ; void *arg0
│    ││╎│   0x100004c1c      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││╎│   0x100004c20      add x0, x27, 1
│    ││╎│   0x100004c24      adrp x8, 0x100007000
│    ││╎│   0x100004c28      add x8, x8, 0xf80                         ; 0x100007f80 ; "\n\nPublic Key (Hex): "
│    ││╎│   0x100004c2c      sub x8, x8, 0x20
│    ││╎│   0x100004c30      orr x1, x8, 0x8000000000000000
│    ││╎│   0x100004c34      sub x20, x29, 0x80
│    ││╎│   0x100004c38      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004c3c      mov x20, x23
│    ││╎│   0x100004c40      bl sym CryptoKit.P256.Signing.PublicKey.rawRepresentation.Foundation.Data...Vvg ; sym.imp.CryptoKit.P256.Signing.PublicKey.rawRepresentation.Foundation.Data...Vvg
│    ││╎│   0x100004c44      mov x20, x0
│    ││╎│   0x100004c48      mov x24, x1
│    ││╎│   0x100004c4c      bl sym.func.100004000
│    ││╎│   0x100004c50      mov x21, x0
│    ││╎│   0x100004c54      mov x0, x20                               ; void *arg0
│    ││╎│   0x100004c58      mov x1, x24                               ; int64_t arg2
│    ││╎│   0x100004c5c      bl sym.func.100004f58
│    ││╎│   0x100004c60      stur x21, [x29, -0x98]
│    ││╎│   0x100004c64      sub x20, x29, 0x98
│    ││╎│   0x100004c68      mov x0, 0
│    ││╎│   0x100004c6c      mov x1, -0x2000000000000000
│    ││╎│   0x100004c70      sub x8, x29, 0x28
│    ││╎│   0x100004c74      ldur x2, [x8, -0x100]
│    ││╎│   0x100004c78      sub x8, x29, 0x30
│    ││╎│   0x100004c7c      ldur x3, [x8, -0x100]
│    ││╎│   0x100004c80      bl sym Element...F                        ; sym.imp.Element...F
│    ││╎│   0x100004c84      mov x24, x0
│    ││╎│   0x100004c88      mov x25, x1
│    ││╎│   0x100004c8c      mov x0, x21                               ; void *arg0
│    ││╎│   0x100004c90      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││╎│   0x100004c94      sub x20, x29, 0x80
│    ││╎│   0x100004c98      mov x0, x24
│    ││╎│   0x100004c9c      mov x1, x25
│    ││╎│   0x100004ca0      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004ca4      mov x0, x25                               ; void *arg0
│    ││╎│   0x100004ca8      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││╎│   0x100004cac      adrp x8, 0x100007000
│    ││╎│   0x100004cb0      add x8, x8, 0xfa0                         ; 0x100007fa0 ; "\n\nSignature (Hex): "
│    ││╎│   0x100004cb4      sub x8, x8, 0x20
│    ││╎│   0x100004cb8      orr x1, x8, 0x8000000000000000
│    ││╎│   0x100004cbc      sub x20, x29, 0x80
│    ││╎│   0x100004cc0      mov x0, 0x13
│    ││╎│   0x100004cc4      movk x0, 0xd000, lsl 48
│    ││╎│   0x100004cc8      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004ccc      sub x20, x29, 0x80
│    ││╎│   0x100004cd0      sub x8, x29, 0x20
│    ││╎│   0x100004cd4      ldur x0, [x8, -0x100]
│    ││╎│   0x100004cd8      sub x8, x29, 0x18
│    ││╎│   0x100004cdc      ldur x24, [x8, -0x100]
│    ││╎│   0x100004ce0      mov x1, x24
│    ││╎│   0x100004ce4      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004ce8      sub x0, x27, 3
│    ││╎│   0x100004cec      adrp x8, 0x100007000
│    ││╎│   0x100004cf0      add x8, x8, 0xfc0                         ; 0x100007fc0 ; "\n\nVerification: "
│    ││╎│   0x100004cf4      sub x8, x8, 0x20
│    ││╎│   0x100004cf8      orr x1, x8, 0x8000000000000000
│    ││╎│   0x100004cfc      sub x20, x29, 0x80
│    ││╎│   0x100004d00      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004d04      sub x20, x29, 0x80
│    ││╎│   0x100004d08      ldur x0, [x29, -0xc0]
│    ││╎│   0x100004d0c      mov x1, x26
│    ││╎│   0x100004d10      bl sym append...ySSF                      ; sym.imp.append...ySSF
│    ││╎│   0x100004d14      ldp x8, x21, [x29, -0x80]
│    ││╎│   0x100004d18      ldur x10, [x29, -0xb0]
│    ││╎│   0x100004d1c      ldur x9, [x29, -0xa8]
│    ││╎│   0x100004d20      stp x10, x9, [x29, -0x80]
│    ││╎│   0x100004d24      ldur x9, [x29, -0xa0]
│    ││╎│   0x100004d28      stur x9, [x29, -0x70]
│    ││╎│   0x100004d2c      stp x8, x21, [x29, -0x98]
│    ││╎│   0x100004d30      mov x0, x21                               ; void *arg0
│    ││╎│   0x100004d34      bl sym.imp.swift_bridgeObjectRetain       ; void *swift_bridgeObjectRetain(void *arg0)
│    ││╎│   0x100004d38      adrp x0, segment.__DATA                   ; 0x100010000
│    ││╎│   0x100004d3c      add x0, x0, 0x108                         ; int64_t arg1
│    ││╎│   0x100004d40      bl sym.func.100004e0c
│    ││╎│   0x100004d44      mov x1, x0
│    ││╎│   0x100004d48      sub x0, x29, 0x98
│    ││╎│   0x100004d4c      sub x20, x29, 0x80
│    ││╎│   0x100004d50      bl sym SwiftUI.State.wrappedValue...s     ; sym.imp.SwiftUI.State.wrappedValue...s
│    ││╎│   0x100004d54      ldp x8, x1, [x29, -0xe0]
│    ││╎│   0x100004d58      ldr x8, [x8, 8]
│    ││╎│   0x100004d5c      mov x0, x28
│    ││╎│   0x100004d60      blr x8
│    ││╎│   0x100004d64      ldp x8, x1, [x29, -0xf8]
│    ││╎│   0x100004d68      ldr x8, [x8, 8]
│    ││╎│   0x100004d6c      mov x0, x23
│    ││╎│   0x100004d70      blr x8
│    ││╎│   0x100004d74      sub x8, x29, 0x10
│    ││╎│   0x100004d78      ldur x8, [x8, -0x100]
│    ││╎│   0x100004d7c      ldr x8, [x8, 8]
│    ││╎│   0x100004d80      ldur x0, [x29, -0xe8]
│    ││╎│   0x100004d84      sub x9, x29, 8
│    ││╎│   0x100004d88      ldur x1, [x9, -0x100]
│    ││╎│   0x100004d8c      blr x8
│    ││╎│   0x100004d90      mov x0, x24                               ; void *arg0
│    ││╎│   0x100004d94      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││╎│   0x100004d98      mov x0, x26                               ; void *arg0
│    ││╎│   0x100004d9c      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││╎│   0x100004da0      mov x0, x21                               ; void *arg0
│    ││╎│   0x100004da4      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││╎│   0x100004da8      ldp x0, x1, [x29, -0xd0]                  ; int64_t arg2
│    ││╎│   0x100004dac      bl sym.func.100005064
│    ││└──< 0x100004db0      b 0x100004998
│    ││ │   ; CODE XREF from sym.func.1000046dc @ 0x100004a64(x)
│    ││ └─> 0x100004db4      ldur x0, [x29, -0xa8]                     ; void *arg0
│    ││     0x100004db8      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│    ││     0x100004dbc      ldur x0, [x29, -0xa0]                     ; void *arg0
│    ││     0x100004dc0      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
│    ││     0x100004dc4      brk 1
│    ││     ; CODE XREF from sym.func.1000046dc @ 0x100004bc8(x)
│    └────> 0x100004dc8      ldur x0, [x29, -0xa8]                     ; void *arg0
│     │     0x100004dcc      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│     │     0x100004dd0      ldur x0, [x29, -0xa0]                     ; void *arg0
│     │     0x100004dd4      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
│     │     0x100004dd8      brk 1
│     │     ; CODE XREF from sym.func.1000046dc @ 0x100004aac(x)
│     └───> 0x100004ddc      ldur x0, [x29, -0xa8]                     ; void *arg0
│           0x100004de0      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│           0x100004de4      ldur x0, [x29, -0xa0]                     ; void *arg0
│           0x100004de8      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
│           0x100004dec      adrp x1, 0x100007000
│           0x100004df0      add x1, x1, 0xf40                         ; 0x100007f40 ; "MASTestApp/MastgTest.swift"
│           0x100004df4      mov x0, x21                               ; void *arg0
│           0x100004df8      mov w2, 0x1a
│           0x100004dfc      mov w3, 1
│           0x100004e00      mov w4, 0x1b
│           0x100004e04      bl sym.imp.swift_unexpectedError          ; void swift_unexpectedError(void *arg0)
└           0x100004e08      brk 1
