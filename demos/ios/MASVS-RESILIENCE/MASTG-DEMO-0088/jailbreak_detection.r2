e asm.bytes=false
e scr.color=false
e asm.var=false

?e

?e search for jailbreak path:

/ /Applications/Cydia.app
/ /Applications/Sileo.app
/ /Applications/Zebra.app
/ /usr/sbin/sshd
/ /usr/bin/ssh
/ /var/cache/apt
/ /var/lib/apt
/ /var/lib/cydia
/ /var/log/syslog
/ /bin/bash
/ /bin/sh
/ /etc/apt
/ /private/jailbreak.txt
/ /private/var/mobile/Library/jailbreak.txt

?e

?e search for urlSchemes:

/ cydia://
/ sileo://
/ zebra://
/ filza://

?e

?e search for suspiciousEnvVars:

/ DYLD_INSERT_LIBRARIES
/ DYLD_FRAMEWORK_PATH
/ DYLD_LIBRARY_PATH

?e

?e Searching for Jailbreak output:

iz~+jail


?e

?e xrefs to Jailbreak strings:
axt 0x10011db00

?e

?e Disassembled Jailbreak function:

pdf @ 0x100008c14
