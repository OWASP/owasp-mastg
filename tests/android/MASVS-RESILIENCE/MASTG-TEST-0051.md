---
masvs_v1_id:
- MSTG-RESILIENCE-9
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: android
title: Testing Obfuscation
masvs_v1_levels:
- R
---

## Overview

## Static Analysis

[Decompile the APK](../../../Document/0x05c-Reverse-Engineering-and-Tampering.md#decompiling-java-code) and [review it](../../../Document/0x05c-Reverse-Engineering-and-Tampering.md#reviewing-decompiled-java-code) to determine whether the codebase has been obfuscated.

Below you can find a sample for an obfuscated code block:

```java
package com.a.a.a;

import com.a.a.b.a;
import java.util.List;

class a$b
  extends a
{
  public a$b(List paramList)
  {
    super(paramList);
  }

  public boolean areAllItemsEnabled()
  {
    return true;
  }

  public boolean isEnabled(int paramInt)
  {
    return true;
  }
}
```

Here are some considerations:

- Meaningful identifiers, such as class names, method names, and variable names, might have been discarded.
- String resources and strings in binaries might have been encrypted.
- Code and data related to the protected functionality might be encrypted, packed, or otherwise concealed.

For native code:

- [libc APIs](https://man7.org/linux/man-pages/dir_section_3.html) (e.g open, read) might have been replaced with OS [syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html).
- [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator "Obfuscator-LLVM") might have been applied to perform ["Control Flow Flattening"](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening) or ["Bogus Control Flow"](https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow).

Some of these techniques are discussed and analyzed in the blog post ["Security hardening of Android native code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) by Gautam Arvind and in the ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) presentation by Eduardo Novella.

For a more detailed assessment, you need a detailed understanding of the relevant threats and the obfuscation methods used. Tools such as [APKiD](../../../Document/0x08a-Testing-Tools.md#apkid) may give you additional indications about which techniques were used for the target app such as obfuscators, packers and anti-debug measures.

## Dynamic Analysis

You can use [APKiD](../../../Document/0x08a-Testing-Tools.md#apkid) to detect if the app has been obfuscated.

Example using the [UnCrackable App for Android Level 4](../../../Document/0x08b-Reference-Apps.md#android-uncrackable-l4):

```sh
apkid owasp-mastg/Crackmes/Android/Level_04/r2pay-v1.0.apk
[+] APKiD 2.1.2 :: from RedNaga :: rednaga.io
[*] owasp-mastg/Crackmes/Android/Level_04/r2pay-v1.0.apk!classes.dex
 |-> anti_vm : Build.TAGS check, possible ro.secure check
 |-> compiler : r8
 |-> obfuscator : unreadable field names, unreadable method names
```

In this case it detects that the app has unreadable field names and method names, among other things.
