---
title: Checking if Native Libraries Contain Debugging Information
platform: android
---

A binary is considered stripped if it has had its @MASTG-KNOW-0008 removed. This is often done to reduce the size of the binary and to protect sensitive information.

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

Even if a tool detects that a binary is stripped, it may still contain some debug information. See @MASTG-TECH-0141 for more details on how to extract and analyze debugging symbols.
