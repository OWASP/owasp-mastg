---
title: Checking if Native Libraries Contain Debugging Information
platform: android
---


Native libraries in Android are typically written in C or C++ using the NDK and compiled into ELF `.so` files, which are stored in the `lib/` directory of the APK. These libraries may contain important functions, including those exposed through the Java Native Interface (JNI). **Debug symbols** in these binaries provide details such as function names, source file references, and variable names. This information is crucial for reverse engineering, vulnerability analysis, and understanding the binary's behavior.

In production builds, debug symbols are usually stripped to reduce file size and make analysis more difficult. However, if symbols are retained, or if you are analyzing a debug build or internal release, you can extract them using the tools described below.

According to the ["Tool Interface Standards (TIS) Executable and Linking Format (ELF 1.2)"](https://refspecs.linuxfoundation.org/elf/elf.pdf) official specification, ELF files can contain various sections that hold debugging information. The most relevant sections for debugging symbols include:

- **Symbol Table (`.symtab`)**: An object file's symbol table holds information needed to locate and relocate a program's symbolic definitions and references.
- **String Table (`.strtab`)**: An object file's string table holds the names of the symbols defined in the file.

The ["DWARF Debugging Information Format"](https://dwarfstd.org/doc/DWARF5.pdf) official specification defines a series of debugging information entries (DIEs) that may be present in binaries as sections. They include, for example:

- **Compilation Unit (`.debug_info`)**: Contains the high-level structure of the source code, including file names, function definitions, and variable scopes.
- **Line Number Information (`.debug_line`)**: Maps source code lines to machine code instructions, allowing debuggers to correlate execution with source code.
- **String Table (`.debug_str`)**: Contains strings used in the debugging information, such as function names and variable names.
- **Location Lists (`.debug_loc`)**: Provides information about the locations of variables and other data in memory, which is essential for debugging.

If these sections are missing, the binary is considered stripped.

@MASTG-TOOL-0028 can be used to detect this. It maps low-level ELF and DWARF constructs into high-level indicators, making it easier to assess the debug state of a binary at a glance:

- The **`i~stripped,linenum,lsyms`** command summarizes this:
    - `stripped false` if `.symtab`, `.strtab`, or any `.debug_*` sections are present.
    - `linenum true` if `.debug_line` is present and parsed.
    - `lsyms true` if `.symtab` exists and includes local symbols.
- The **`iS`** command lists ELF sections. You can filter for relevant debug and symbol sections using `iS~debug,strtab,symtab`. Their presence means debug data is available.

**Checking the Binaries' Info for Debugging Information:**

To check if a binary is stripped, you can use @MASTG-TOOL-0028 and run the following command:

```bash
[0x00000e3c]> i~stripped,linenum,lsyms
linenum  false
lsyms    false
stripped true
```

In this example, `stripped` is `true`, indicating that debug symbols are not present. `linenum` being `false` means line number information is also missing.

For a binary with debug symbols, the output might look like:

```sh
[0x0003e360]> i~stripped,linenum,lsyms
linenum  true
lsyms    true
stripped false
```

**Checking Sections for Debugging Information:**

If sections such as `.symtab`, `.strtab`, or `.debug_*` are missing, the binary has been stripped.

Example output for a stripped binary:

```bash
[0x00000e3c]> iS~debug,strtab,symtab
```

Example output for a binary with debug symbols:

```sh
[0x0003e360]> iS~debug,strtab,symtab
23  0x000c418c      0x60 0x00000000      0x60 ---- 0x0   PROGBITS    .debug_aranges
24  0x000c41ec  0x14d85c 0x00000000  0x14d85c ---- 0x0   PROGBITS    .debug_info
25  0x00211a48    0xa14f 0x00000000    0xa14f ---- 0x0   PROGBITS    .debug_abbrev
26  0x0021bb97   0x5d6a3 0x00000000   0x5d6a3 ---- 0x0   PROGBITS    .debug_line
27  0x0027923a   0x7c26a 0x00000000   0x7c26a ---- 0x30  PROGBITS    .debug_str
28  0x002f54a4  0x172883 0x00000000  0x172883 ---- 0x0   PROGBITS    .debug_loc
29  0x00467d27      0x20 0x00000000      0x20 ---- 0x0   PROGBITS    .debug_macinfo
30  0x00467d47   0x602d0 0x00000000   0x602d0 ---- 0x0   PROGBITS    .debug_ranges
31  0x0051b12a     0x167 0x00000000     0x167 ---- 0x0   STRTAB      .shstrtab
32  0x004c8018   0x27510 0x00000000   0x27510 ---- 0x0   SYMTAB      .symtab
33  0x004ef528   0x2bc02 0x00000000   0x2bc02 ---- 0x0   STRTAB      .strtab
```
