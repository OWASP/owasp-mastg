---
masvs_category: MASVS-CODE
platform: android
title: Binary Protection Mechanisms
---

Detecting the presence of [binary protection mechanisms](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) heavily depend on the language used for developing the application.

In general all binaries should be tested, which includes both the main app executable as well as all libraries/dependencies. However, on Android we will focus on native libraries since the main executables are considered safe as we will see next.

Android optimizes its Dalvik bytecode from the app DEX files (e.g. classes.dex) and generates a new file containing the native code, usually with an .odex, .oat extension. This Android compiled binary (see "Compiled App Binary" in @MASTG-TECH-0007) is wrapped using the [ELF format](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html) which is the format used by Linux and Android to package assembly code.

The app's NDK native libraries (see "Native Libraries" in @MASTG-TECH-0007) also [use the ELF format](https://developer.android.com/ndk/guides/abis).

- [**PIE (Position Independent Executable)**](0x04h-Testing-Code-Quality.md#position-independent-code):
    - Since Android 7.0 (API level 24), PIC compilation is [enabled by default](https://source.android.com/devices/tech/dalvik/configure) for the main executables.
    - With Android 5.0 (API level 21), support for non-PIE enabled native libraries was [dropped](https://source.android.com/security/enhancements/enhancements50) and since then, PIE is [enforced by the linker](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=430).
- [**Memory management**](0x04h-Testing-Code-Quality.md#memory-management):
    - Garbage Collection will simply run for the main binaries and there's nothing to be checked on the binaries themselves.
    - Garbage Collection does not apply to Android native libraries. The developer is responsible for doing proper [manual memory management](0x04h-Testing-Code-Quality.md#manual-memory-management). See ["Memory Corruption Bugs"](0x04h-Testing-Code-Quality.md#memory-corruption-bugs).
- [**Stack Smashing Protection**](0x04h-Testing-Code-Quality.md#stack-smashing-protection):
    - Android apps get compiled to Dalvik bytecode which is considered memory safe (at least for mitigating buffer overflows). Other frameworks such as Flutter will not compile using stack canaries because of the way their language, in this case Dart, mitigates buffer overflows.
    - It must be enabled for Android native libraries but it might be difficult to fully determine it.
        - NDK libraries should have it enabled since the compiler does it by default.
        - Other custom C/C++ libraries might not have it enabled.

Learn more:

- [Android executable formats](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
- [Android runtime (ART)](https://source.android.com/devices/tech/dalvik/configure#how_art_works)
- [Android NDK](https://developer.android.com/ndk/guides)
- [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)
