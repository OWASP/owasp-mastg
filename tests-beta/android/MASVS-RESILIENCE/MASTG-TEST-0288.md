---
platform: android
title: Debugging Symbols in Native Binaries
alias: debugging-symbols-in-native-binaries
id: MASTG-TEST-0288
type: [static]
weakness: MASWE-0093
best-practices: []
profiles: [R]
---

## Overview

This test checks whether the app includes debugging symbols in its native binaries. Debugging symbols can provide valuable information during reverse engineering and vulnerability analysis by exposing sensitive implementation details such as function names, variable names, and source file references.

## Steps

1. Run a static analysis (@MASTG-TECH-0140) to retrieve any debugging information present in the native libraries.
2. Optionally, use @MASTG-TECH-0141 to obtain debugging symbols from the native libraries.

## Observation

The output should identify all instances of debugging information in the native libraries.

## Evaluation

The test **fails** if debugging information is present in any native binary. This includes any of the following conditions:

- The output from @MASTG-TOOL-0028 shows:

  ```plaintext
  linenum  true
  lsyms    true
  stripped false
  ```

- ELF sections such as `.symtab`, `.strtab`, or any `.debug_*` DWARF sections (e.g. `.debug_info`, `.debug_line`, `.debug_str`) are present.

- Actual debugging symbols (e.g. symbol names, source references) were successfully extracted.
