search for jailbreak path:
0x10015af10 hit4_0 "_proto/Applications/Cydia.app/Applic"
0x10015af30 hit5_0 "dia.app/Applications/Sileo.app/Applic"
0x10015af50 hit6_0 "leo.app/Applications/Zebra.app/Applic"
0x10019ccd8 hit7_0 "`/usr/sbin/sshd/usr/bin/ssh"
0x10019cce8 hit8_0 "/usr/sbin/sshd/usr/bin/ssh/var/cache/a"
0x10019ccf8 hit9_0 "/usr/bin/ssh/var/cache/apt/var/lib/apt"
0x10019cd08 hit10_0 "/var/cache/apt/var/lib/apt/var/lib/cyd"
0x10019cd18 hit11_0 "/var/lib/apt/var/lib/cydia/var/log/syslo"
0x10019cd28 hit12_0 "/var/lib/cydia/var/log/syslog/bin/bash"
0x10019cd38 hit13_0 "/var/log/syslog/bin/bash/bin/sh"
0x10019cd48 hit14_0 "/bin/bash/bin/sh/etc/ap"
0x10019cd58 hit15_0 "/bin/sh/etc/apt"
0x10015b000 hit16_0 "-keysign/private/jailbreak.txt/priva"
0x10015b020 hit17_0 "ak.txt/private/var/mobile/Library/jailbreak.txt_TtC10MAS"

search for urlSchemes:
0x10019cd90 hit18_0 "cydia://sileo://"
0x10019cda0 hit19_0 "cydia://sileo://zebra://"
0x10019cdb0 hit20_0 "sileo://zebra://filza://"
0x10019cdc0 hit21_0 "zebra://filza://"

search for suspiciousEnvVars:
0x10015b0a0 hit22_0 "torDYLD_INSERT_LIBRARIESDYLD_"
0x10015b0c0 hit23_0 "ARIESDYLD_FRAMEWORK_PATHDYL"
0x10015b0e0 hit24_0 "ATHDYLD_LIBRARY_PATHC"

Searching for Jailbreak output:
2    0x0011a030  0x10011a030 17  18   4.__TEXT.__const           ascii   JailbreakDetector
7    0x0015b000  0x10015b000 22  23   5.__TEXT.__cstring         ascii   /private/jailbreak.txt
8    0x0015b020  0x10015b020 41  42   5.__TEXT.__cstring         ascii   /private/var/mobile/Library/jailbreak.txt
10   0x0015b070  0x10015b070 35  36   5.__TEXT.__cstring         ascii   _TtC10MASTestApp17JailbreakDetector
15   0x0015b130  0x10015b130 24  25   5.__TEXT.__cstring         ascii   Device is not jailbroken
16   0x0015b150  0x10015b150 21  22   5.__TEXT.__cstring         ascii   Device is jailbroken!

xrefs to Jailbreak strings:
sym.func.1000058a0 0x1000058e4 [STRN:-w-] add x10, x10, str.Device_is_jailbroken_

Disassembled Jailbreak function:
            ; CODE XREF from sym.func.1000064b8 @ 0x1000064c0(x)
┌ 184: sym.func.1000058a0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg_8h, int64_t arg_18h, int64_t arg_30h, int64_t arg_40h, int64_t arg_50h, int64_t arg_60h);
│           0x1000058a0      sub sp, sp, 0x60
│           0x1000058a4      stp x22, x21, [var_30h]
│           0x1000058a8      stp x20, x19, [var_40h]
│           0x1000058ac      stp x29, x30, [var_50h]
│           0x1000058b0      add x29, var_50h
│           0x1000058b4      mov x19, x2                               ; arg3
│           0x1000058b8      mov x21, x1                               ; arg2
│           0x1000058bc      mov x20, x0                               ; arg1
│           0x1000058c0      mov x0, x2                                ; arg3
│           0x1000058c4      bl sym.imp.swift_retain
│           0x1000058c8      mov x0, x21                               ; void *arg0
│           0x1000058cc      bl sym.imp.swift_bridgeObjectRetain       ; void *swift_bridgeObjectRetain(void *arg0)
│           0x1000058d0      bl sym.func.100004194
│           0x1000058d4      movz x8, 0x15
│           0x1000058d8      movk x8, 0xd000, lsl 48
│           0x1000058dc      add x9, x8, 3
│           0x1000058e0      adrp x10, str._private_jailbreak.txt      ; hit16_0
│                                                                      ; 0x10015b000
│           0x1000058e4      add x10, x10, 0x150                       ; 0x10015b150 ; "Device is jailbroken!"
│           0x1000058e8      adrp x11, str._private_jailbreak.txt      ; hit16_0
│                                                                      ; 0x10015b000
│           0x1000058ec      add x11, x11, 0x130                       ; 0x10015b130 ; "Device is not jailbroken"
│           0x1000058f0      sub x10, x10, 0x20
│           0x1000058f4      sub x11, x11, 0x20
│           0x1000058f8      tst w0, 1
│           0x1000058fc      csel x8, x8, x9, ne
│           0x100005900      orr x9, x11, 0x8000000000000000
│           0x100005904      orr x10, x10, 0x8000000000000000
│           0x100005908      stp x20, x21, [var_18h]
│           0x10000590c      str x19, [var_0h]
│           0x100005910      csel x9, x10, x9, ne
│           0x100005914      stp x8, x9, [var_8h]
│           0x100005918      adrp x0, segment.__DATA                   ; 0x10019c000
│           0x10000591c      add x0, x0, 0xfe8                         ; int64_t arg1
│           0x100005920      bl sym.func.100004920
│           0x100005924      mov x1, x0
│           0x100005928      add x0, arg_8h
│           0x10000592c      add x20, arg_18h
│           0x100005930      bl sym SwiftUI.State.wrappedValue.setter : A ; sym.imp.SwiftUI.State.wrappedValue.setter_:_A
│           0x100005934      mov x0, x19                               ; void *arg0
│           0x100005938      bl sym.imp.swift_release                  ; void swift_release(void *arg0)
│           0x10000593c      mov x0, x21                               ; void *arg0
│           0x100005940      bl sym.imp.swift_bridgeObjectRelease      ; void swift_bridgeObjectRelease(void *arg0)
│           0x100005944      ldp x29, x30, [var_50h]
│           0x100005948      ldp x20, x19, [arg_40h]
│           0x10000594c      ldp x22, x21, [arg_30h]
│           0x100005950      add sp, arg_60h
└           0x100005954      ret
