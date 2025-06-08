---
title: Obtaining Debugging Symbols
platform: ios
---

To retrieve debug symbols from iOS binaries you can use @MASTG-TOOL-0073, @MASTG-TOOL-0121 or @MASTG-TOOL-0041 to inspect all of the app binaries.

## radare2

Using @MASTG-TOOL-0073 with the command `is`:

```bash
r2 -A MASTestApp
[0x100007408]> is~Sec
70  0x00007894 0x100007894 LOCAL  FUNC 0        imp.SecKeyCopyExternalRepresentation
71  0x000078a0 0x1000078a0 LOCAL  FUNC 0        imp.SecKeyCopyPublicKey
72  0x000078ac 0x1000078ac LOCAL  FUNC 0        imp.SecKeyCreateRandomKey
73  0x000078b8 0x1000078b8 LOCAL  FUNC 0        imp.SecKeyCreateSignature
74  0x000078c4 0x1000078c4 LOCAL  FUNC 0        imp.SecKeyVerifySignature
```

Alternatively, you can use @MASTG-TOOL-0129 to [obtain the symbols](https://book.rada.re/tools/rabin2/symbols.html) by running `rabin2 -s MASTestApp`.

## objdump

The following snippet shows how you can apply @MASTG-TOOL-0121 on `MASTestApp` (the iOS main app executable) with the typical output of a binary containing debug symbols. Those are marked with the `d` (debug) flag. Check the [objdump man page](https://www.unix.com/man-page/osx/1/objdump/ "objdump man page") for information about various other symbol flag characters.

```bash
$ objdump --syms MASTestApp | grep " d " | grep "swift"
...
0000000000000000      d  *UND* MastgTest.swift
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftFoundation_$_MASTestApp
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftObjectiveC_$_MASTestApp
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftDarwin_$_MASTestApp
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftCoreFoundation_$_MASTestApp
...
```

## nm

With @MASTG-TOOL-0041 you can compare the symbols from a plain call to `nm` with the output of a call to `nm -a`. The latter also prints the debug symbols. The following command will show only debug symbols in a diff format. If this is empty, now debug symbols are present.

```bash
$ diff <(nm MASTestApp) <(nm -a MASTestApp)
...
28a228
> 0000000100009928 - 01 0000   FUN _$s10MASTestApp11ContentViewV7SwiftUI0D0AadEP05_makeD4List4view6inputsAD01_dH7OutputsVAD11_GraphValueVyxG_AD01_dH6InputsVtFZTW
30a231
> 000000010000992c - 01 0000   FUN _$s10MASTestApp11ContentViewV7SwiftUI0D0AadEP14_viewListCount6inputsSiSgAD01_dhI6InputsV_tFZTW
31a233,234
> 0000000100009944 - 01 0000   FUN _$s10MASTestApp11ContentViewV7SwiftUI0D0AadEP4body4BodyQzvgTW
> 0000000000000000 - 00 0000  GSYM _$s10MASTestApp11ContentViewVAC7SwiftUI0D0AAWL
32a236
> 000000010000a220 - 01 0000   FUN _$s10MASTestApp11ContentViewVAC7SwiftUI0D0AAWl
...
```
