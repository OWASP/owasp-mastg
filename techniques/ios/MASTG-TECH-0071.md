---
title: Retrieving Strings
platform: ios
---

Strings are always a good starting point while analyzing a binary, as they provide context to the associated code. For instance, an error log string such as "Cryptogram generation failed" gives us a hint that the adjoining code might be responsible for the generation of a cryptogram.

In order to extract strings from an iOS binary, you can use GUI tools such as Ghidra or [iaito](https://github.com/radareorg/iaito "iaito") or rely on CLI-based tools such as the _strings_ Unix utility (`strings <path_to_binary>`) or radare2's @MASTG-TOOL-0129 (`rabin2 -zz <path_to_binary>`). When using the CLI-based ones you can take advantage of other tools such as grep (e.g. in conjunction with regular expressions) to further filter and analyze the results.
