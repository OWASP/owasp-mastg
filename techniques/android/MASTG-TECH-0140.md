---
title: Checking if Native Libraries Contain Debugging Information
platform: android
---

## Overview

On Android, native libraries are usually developed in C or C++ with the NDK and compiled into ELF shared objects with a .so extension, which reside in the `lib/` directory of the APK. These libraries often expose functionality to be used from Dalvik through the Java Native Interface (JNI). **Debug symbols** in these binaries provide details like function names, variable names, and source file mappings, which are useful for reverse engineering, debugging, and security analysis.

When compiling and linking programs, symbols represent functions or variables. In ELF (Executable and Linkable Format) files, symbols have different roles:

- **Local symbols**: Only visible inside the file where they're defined. Used internally. Not accessible from other files.
- **Global symbols**: Visible to other files. Used to share functions or variables across different object files.
- **Weak symbols**: Like global symbols, but lower priority. A strong (non-weak) symbol overrides a weak one if both exist.

In production builds, debug information must be stripped to reduce binary size and limit information disclosure. However, debug or internal builds may retain symbols either within the binary or in separate companion files.

Symbol visibility is often mishandled, leading to unintended external exposure of symbols and requiring manual inspection.


### Symbol Tables and DWARF Sections

The [ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) format defines which sections must be used to store symbol information:

- **`.symtab`**: The full symbol table used at link time, often removed in production binaries (`DT_SYMTAB` dtag).
- **`.dynsym`**: The dynamic symbol table, used for runtime linking. It is always present in shared objects.

[DWARF](https://dwarfstd.org/doc/DWARF5.pdf) is the standard debug format used in ELF binaries (but it is also used in other UNIX-based systems like for MACH-O binaries in the Apple ecosystem). Key sections include:

- **`.debug_info`**: Contains the main debugging information, including types, function definitions, and scopes.
- **`.debug_line`**: Maps machine code to source code line numbers.
- **`.debug_str`**: Stores strings used by DWARF entries.
- **`.debug_loc`, `.debug_ranges`, `.debug_abbrev`, etc.**: Support detailed debug metadata.

Additionally, some toolchains use zlib [compression](https://www.linker-aliens.org/blogs/ali/entry/elf_section_compression/) for DWARF data to reduce binary size (for example [clang](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-gz) and [gcc](https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html#index-gz) support this using the `-gz` option). These sections are typically named using a `.z` prefix (e.g.,`.zdebug_info`, `.zdebug_line`, `.zdebug_str`, etc.) and contain the same information as their uncompressed counterparts. Some analysis tools that do not support these may incorrectly report the binary as stripped.

To check for the presence of these sections in a binary, you can use @MASTG-TOOL-0121 (with the option `-x`) or @MASTG-TOOL-0028 (`iS` command) and other tools like `readelf`.

For example, using radare2:

```sh
[0x0003e360]> iS~debug,symtab,SYMTAB
23  0x000c418c      0x60 0x00000000      0x60 ---- 0x0   PROGBITS    .debug_aranges
24  0x000c41ec  0x14d85c 0x00000000  0x14d85c ---- 0x0   PROGBITS    .debug_info
25  0x00211a48    0xa14f 0x00000000    0xa14f ---- 0x0   PROGBITS    .debug_abbrev
26  0x0021bb97   0x5d6a3 0x00000000   0x5d6a3 ---- 0x0   PROGBITS    .debug_line
27  0x0027923a   0x7c26a 0x00000000   0x7c26a ---- 0x30  PROGBITS    .debug_str
28  0x002f54a4  0x172883 0x00000000  0x172883 ---- 0x0   PROGBITS    .debug_loc
29  0x00467d27      0x20 0x00000000      0x20 ---- 0x0   PROGBITS    .debug_macinfo
30  0x00467d47   0x602d0 0x00000000   0x602d0 ---- 0x0   PROGBITS    .debug_ranges
32  0x004c8018   0x27510 0x00000000   0x27510 ---- 0x0   SYMTAB      .symtab
```

**IMPORTANT**: The presence of these sections doesn't necessarily indicate that the binary hasn't been stripped. Some toolchains may retain these sections even in stripped binaries, but they are often empty or contain minimal information. Ultimately, what matters is **whether the symbols themselves are still present**. See @MASTG-TECH-0141 for more details on how to extract and analyze debugging symbols.

### External Debug Symbol Files

The [Android Developers documentation](https://developer.android.com/build/include-native-symbols) explains that native libraries in release builds are stripped by default. To enable symbolicated native crash reports, you must generate a separate debug symbols file—typically located at `<variant>/native-debug-symbols.zip`—and upload it to the Google Play Console. This ZIP archive contains full **unstripped `.so` files** with embedded DWARF debug information. The DWARF data is not split into separate files (such as `.dwo`) but remains inside each `.so`.

> This symbolication process is analogous to uploading a `mapping.txt` file to [deobfuscate stack traces](https://support.google.com/googleplay/android-developer/answer/9848633) for ProGuard or R8 obfuscated Java/Kotlin code.

In contrast, iOS uses an approach **similar in spirit** to [split DWARF](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-gsplit-dwarf), familiar from Linux toolchains. According to the [Apple Developer documentation](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information), enabling the `DWARF with dSYM File` option in Xcode generates separate debug symbol files (`.dSYM`) for release builds. These can be uploaded to Apple's symbol servers for crash report symbolication.

## Checking the Binaries' Info for Debugging Information

To check if a binary is stripped, you can use @MASTG-TOOL-0028 and run the following command:

```sh
[0x0003e360]> i~stripped,linenum,lsyms
linenum  true
lsyms    true
stripped false
```

In this example:

- `stripped` is `false`, indicating that debug symbols are present.
- `linenum` is `true`, meaning line number information is also available.
- `lsyms` is `true`, indicating that local symbols are present.
