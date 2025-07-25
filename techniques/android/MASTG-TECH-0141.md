---
title: Obtaining Debugging Symbols from Native Libraries
platform: android
---

If a binary is not stripped, you can extract debugging symbols from native libraries using standard ELF inspection tools. These symbols can provide insights into the functions and variables used in the binary, which is useful for reverse engineering and vulnerability analysis.

If debug symbols are stripped:

- You'll only see exported (dynamic) symbols from `.dynsym`, but not local or static symbols from `.symtab`, which are typically stripped in production builds.
- No information such as function arguments, line numbers, or local variables will be available.

## radare2

Using @MASTG-TOOL-0028, you can list imported and exported symbols parsed from ELF symbol tables with the command `is`:

```bash
r2 -A libnative-lib.so
[0x00000e3c]> is
nth paddr      vaddr      bind   type   size lib name                                                          demangled
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
3   0x00000e78 0x00000e78 GLOBAL FUNC   16       Java_sg_vantagepoint_helloworldjni_MainActivity_stringFromJNI
4   0x00001578 0x00001578 GLOBAL FUNC   4        __aeabi_unwind_cpp_pr0
5   ---------- 0x00003004 GLOBAL NOTYPE 0        _edata
6   ---------- 0x00003004 GLOBAL NOTYPE 0        _end
7   ---------- 0x00003004 GLOBAL NOTYPE 0        __bss_start
10  0x0000157c 0x0000157c WEAK   FUNC   4        __aeabi_unwind_cpp_pr1
11  0x00001580 0x00001580 WEAK   FUNC   4        __aeabi_unwind_cpp_pr2
13  0x000017dc 0x000017dc GLOBAL FUNC   0        __gnu_Unwind_Restore_VFP_D
...
```

Note that the output includes virtual and physical addresses, symbol binding (`GLOBAL` or `LOCAL`), type (`FUNC` or `OBJECT`), and name.

If you're interested in JNI symbols, you can filter the output with `~JNI`.

Alternatively, you can use @MASTG-TOOL-0129 to [obtain the symbols](https://book.rada.re/tools/rabin2/symbols.html) by running `rabin2 -s libnative-lib.so | grep JNI`.

## objdump

You can use `objdump` to inspect ELF files for debugging symbols using the command `objdump --syms`:

```sh
objdump --syms libnative-lib.so

libnative-lib.so:       file format elf32-littlearm

SYMBOL TABLE:
```

In this case, the output shows that there are no symbols available, indicating that the binary is stripped.

```sh
objdump --syms libunstripped.so | head

libunstripped.so: file format elf32-littlearm

SYMBOL TABLE:
00000000 l    df *ABS*  00000000 crtbegin_so.c
000315d8 l       .text  00000000 $a.0
000315e8 l       .text  00000000 $a.2
0003161c l       .text  00000000 $a.4
000315e4 l       .text  00000000 $d.1
00031614 l       .text  00000000 $d.3
...
```

You can use `objdump -x` to display all section headers. If only `.dynsym` appears and `.symtab` is absent, the binary has been stripped of debug symbols.

Example of a stripped binary:

```sh
objdump -x libnative-lib.so | grep '\.symtab\|\.dynsym'

  2 .dynsym                00000370 00000158 
```

Example of a binary with debug symbols:

```sh
objdump -x libunstripped.so | grep -E 'strtab|symtab'
 34 .symtab                00079ac0 00000000
 35 .strtab                00034c42 00000000
 36 .shstrtab              00000194 00000000
```

## nm

With @MASTG-TOOL-0003 you can retrieve symbol tables from ELF files.

```bash
nm libnative-lib.so 
libnative-lib.so: no symbols
```

This shows globally available function names and variables if the binary retains symbols. `nm -a` displays all symbols, including local (static) ones, which are only available if `.symtab` is present.

To identify the presence of debug symbols, compare the output of both commands:

```bash
diff <(nm libnative-lib.so) <(nm -a libnative-lib.so)
```

If the output is empty, debug symbols were stripped. If you see entries with function names or source references, symbols are present.

```sh
diff <(nm libunstripped.so) <(nm -a libunstripped.so) | tail
3871a31083,31086
> 00000000 a stdexcept.cpp
> 00000000 a stdlib_exception.cpp
> 00000000 a stdlib_stdexcept.cpp
> 00000000 a stdlib_typeinfo.cpp
3875a31091
> 00000000 a string.cpp
3888a31105,31106
> 00000000 a system_error.cpp
> 00000000 a thread.cpp
```
