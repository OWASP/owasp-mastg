Uses of CryptoKit.P256.Signing.PrivateKey:
0x100007364    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey.public...F0AE06PublicF0Vvg.Public...F0Vvg...Vvg
0x100007370    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey.rawRepresentation.Foundation.ContiguousBytes...lufC
0x10000737c    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey.signature.for.ECDSASignature.Foundation.DataProtocol...lF
0x100007388    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey...VMa

xrefs to CryptoKit.P256.Signing.PrivateKey.rawRepresentation:
sym.func.1000046dc 0x1000047f0 [CALL:--x] bl sym.imp.CryptoKit.P256.Signing.PrivateKey...VMa

Use of CryptoKit.P256.Signing.PrivateKey.rawRepresentation:
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
