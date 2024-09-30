!printf "\n\n"

!printf "Uses of CryptoKit.Insecure functions:\n"
afl~Insecure.

!printf "\n"

!printf "xrefs to CryptoKit.Insecure.MD5:\n"
axt @ 0x100007280

!printf "\n"

!printf "xrefs to CryptoKit.Insecure.SHA1:\n"
axt @ 0x10000728c

!printf "\n"

!printf "Use of MD5:\n"
pd-- 5 @ 0x1000046d8

!printf "\n"

!printf "Use of SHA1:\n"
pd-- 5 @ 0x100004214
