e asm.bytes = false
e scr.color=false

!printf "Uses of CryptoKit.P256.Signing.PrivateKey:\n"
afl~CryptoKit.P256.Signing.PrivateKey

!printf "\n"

!printf "xrefs to CryptoKit.P256.Signing.PrivateKey.rawRepresentation:\n"
axt @ 0x100007388

!printf "\n"

!printf "Use of CryptoKit.P256.Signing.PrivateKey.rawRepresentation:\n"

pd-- 9 @ 0x1000048d4

pdf @ sym.func.1000046dc > function.asm

px 32 @ 0x1000100c8 > key.asm