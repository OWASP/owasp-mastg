# jailbreak_detection.r2
e asm.bytes=false
e scr.color=false
e asm.var=false

?e

?e search for root path:

/ /system/app/Superuser.apk
/ /system/xbin/daemonsu
/ /system/xbin/su
/ /sbin/su
/ /system/bin/su
/ /system/sd/xbin/su
/ /system/bin/failsafe/su
/ /data/local/su
/ /data/local/xbin/su
/ /data/local/bin/su

?e

?e search for urlSchemes:

/ supersu://
/ magisk://

?e

?e search for suspiciousEnvVars:

/ LD_PRELOAD
/ LD_LIBRARY_PATH

?e

?e Searching for Root output:

iz~+root

?e

?e xrefs to Root strings:
axt 0x10011db00

?e

?e Disassembled Root function:

pdf @ 0x100008c14
