!printf "\n\n"

!printf "Uses of CommonCrypto hash function:\n"
afl~CC_

!printf "\n"

!printf "xrefs to CC_MD5:\n"
axt @ 0x1000071a8

!printf "xrefs to CC_SHA1:\n"
axt @ 0x1000071b4

!printf "\n"

!printf "Use of MD5:\n"
pd-- 5 @ 0x1000048c4

!printf "\n"

!printf "Use of SHA1:\n"
pd-- 5 @ 0x10000456c
