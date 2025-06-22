---
masvs_v1_id:
- MSTG-STORAGE-10
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: Testing Memory for Sensitive Data
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

## Static Analysis

When performing static analysis for sensitive data exposed via memory, you should

- try to identify application components and map where the data is used,
- make sure that sensitive data is handled with as few components as possible,
- make sure that object references are properly removed once the object containing sensitive data is no longer needed,
- make sure that highly sensitive data is overwritten as soon as it is no longer needed,
- not pass such data via immutable data types, such as `String` and `NSString`,
- avoid non-primitive data types (because they might leave data behind),
- overwrite the value in memory before removing references,
- pay attention to third-party components (libraries and frameworks). Having a public API that handles data according to the recommendations above is a good indicator that developers considered the issues discussed here.

## Dynamic Analysis

There are several approaches and tools available for dynamically testing the memory of an iOS app for sensitive data.

### Retrieving and Analyzing a Memory Dump

Whether you are using a jailbroken or a non-jailbroken device, you can dump the app's process memory with @MASTG-TOOL-0038 and @MASTG-TOOL-0106. You can find a detailed explanation of this process in @MASTG-TECH-0044.

After the memory has been dumped (e.g. to a file called "memory"), depending on the nature of the data you're looking for, you'll need a set of different tools to process and analyze that memory dump. For instance, if you're focusing on strings, it might be sufficient for you to execute the command `strings` or `rabin2 -zz` from @MASTG-TOOL-0129 to extract those strings.

```bash
# using strings
$ strings memory > strings.txt

# using rabin2
$ rabin2 -ZZ memory > strings.txt
```

Open `strings.txt` in your favorite editor and dig through it to identify sensitive information.

However if you'd like to inspect other kind of data, you'd rather want to use radare2 and its search capabilities. See radare2's help on the search command (`/?`) for more information and a list of options. The following shows only a subset of them:

```bash
$ r2 <name_of_your_dump_file>

[0x00000000]> /?
Usage: /[!bf] [arg]  Search stuff (see 'e??search' for options)
|Use io.va for searching in non virtual addressing spaces
| / foo\x00                    search for string 'foo\0'
| /c[ar]                       search for crypto materials
| /e /E.F/i                    match regular expression
| /i foo                       search for string 'foo' ignoring case
| /m[?][ebm] magicfile         search for magic, filesystems or binary headers
| /v[1248] value               look for an `cfg.bigendian` 32bit value
| /w foo                       search for wide string 'f\0o\0o\0'
| /x ff0033                    search for hex string
| /z min max                   search for strings of given size
...
```

### Runtime Memory Analysis

Perform @MASTG-TECH-0096, e.g., using @MASTG-TOOL-0036, to analyze and inspect the app's memory while running and without needing to dump it.

For example, you may run the previous search commands from r2frida and search the memory for a string, hexadecimal values, etc. When doing so, remember to prepend the search command (and any other r2frida specific commands) with a backslash `:` after starting the session with `r2 frida://usb//<name_of_your_app>`.
