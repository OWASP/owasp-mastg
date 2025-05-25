---
title: Obtaining Compiler-Provided Security Features
platform: ios
---

The iOS compiler provides several [security features that can be enabled during compilation](../../Document/0x06i-Testing-Code-Quality-and-Build-Settings.md/#binary-protection-mechanisms). These features help protect the application from common vulnerabilities like buffer overflows and memory leaks. This technique provides guidance on how to check if these features are enabled in the compiled binary.

## @MASTG-TOOL-0073

In radare2, the presence of these compiler-provided security features can be checked by using the `i` and `is` commands.

**Check for PIC and Canaries:** Using the `i` command, you can check if the binary has Position Independent Code (PIC) enabled (`pic`) and if it has stack canaries (`canary`).

```sh
r2 MASTestApp
[0x100007408]> i~canary,pic
canary   true
pic      true
```

The output shows that the binary has stack canaries and PIE enabled.

**Check for ARC:** Using the `is` command, you can list the symbols in the binary and check for symbols that indicate the usage of Automatic Reference Counting (ARC). Common ARC symbols include:

- `objc_autorelease`
- `objc_retainAutorelease`
- `objc_release`
- `objc_retain`
- `objc_retainAutoreleasedReturnValue`
- `swift_release`
- `swift_retain`

An iOS binary does not need to have all of these symbols to be considered ARC-enabled, but the presence of some of them indicates that ARC is used.

```sh
[0x100007408]> is~release,retain
80  0x0000790c 0x10000790c LOCAL  FUNC 0        imp.objc_release_x20
81  0x00007918 0x100007918 LOCAL  FUNC 0        imp.objc_release_x24
82  0x00007924 0x100007924 LOCAL  FUNC 0        imp.objc_release_x25
83  0x00007930 0x100007930 LOCAL  FUNC 0        imp.objc_release_x27
84  0x0000793c 0x10000793c LOCAL  FUNC 0        imp.objc_release_x8
85  0x00007948 0x100007948 LOCAL  FUNC 0        imp.objc_retainAutoreleasedReturnValue
86  0x00007954 0x100007954 LOCAL  FUNC 0        imp.objc_retain_x23
101 0x00007a08 0x100007a08 LOCAL  FUNC 0        imp.swift_release
102 0x00007a14 0x100007a14 LOCAL  FUNC 0        imp.swift_retain
```

The output shows that the binary contains symbols indicating the usage of ARC.

## @MASTG-TOOL-0074

Objection has a command `ios info binary` which can be used to get information about the binary, including whether stack canaries and PIE are enabled.

```sh
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```

The output shows `PIE`, `ARC` and `Canary` with a value of `True` or `False`.
