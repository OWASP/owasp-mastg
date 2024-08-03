---
title: Retrieving Strings
platform: android
---

While performing any kind of binary analysis, strings can be considered as one of the most valuable starting points as they provide context. For example, an error log string like "Data encryption failed." gives us a hint that the adjoining code might be responsible for performing some kind of encryption operation.

## Java and Kotlin Bytecode

As we already know, all the Java and Kotlin bytecode of an Android application is compiled into a DEX file. Each DEX file contains a [list of string identifiers](https://source.android.com/devices/tech/dalvik/dex-format#file-layout "string identifiers list") (strings_ids), which contains all the string identifiers used in the binary whenever a string is referred, including internal naming (e.g, type descriptors) or constant objects referred by the code (e.g hardcoded strings). You can simply dump this list using tools such as Ghidra (GUI based) or [Dextra](http://www.newandroidbook.com/tools/dextra.html "Dextra") (CLI based).

With Ghidra, strings can be obtained by simply loading the DEX file and selecting **Window -> Defined strings** in the menu.

> Loading an APK file directly into Ghidra might lead to inconsistencies. Thus it is recommended to extract the DEX file by unzipping the APK file and then loading it into Ghidra.

<img src="Images/Chapters/0x05c/ghidra_dex_strings.png" width="100%" />

With Dextra, you can dump all the strings using the following command:

```bash
dextra -S classes.dex
```

The output from Dextra can be manipulated using standard Linux commands, for example, using `grep` to search for certain keywords.

It is important to know, the list of strings obtained using the above tools can be very big, as it also includes the various class and package names used in the application. Going through the complete list, specially for big binaries, can be very cumbersome. Thus, it is recommended to start with keyword-based searching and go through the list only when keyword search does not help. Some generic keywords which can be a good starting point are - password, key, and secret. Other useful keywords specific to the context of the app can be obtained while you are using the app itself. For instance, imagine that the app has as login form, you can take note of the displayed placeholder or title text of the input fields and use that as an entry point for your static analysis.

## Native Code

In order to extract strings from native code used in an Android application, you can use GUI tools such as Ghidra or [iaito](https://github.com/radareorg/iaito "iaito") or rely on CLI-based tools such as the _strings_ Unix utility (`strings <path_to_binary>`) or radare2's rabin2 (`rabin2 -zz <path_to_binary>`). When using the CLI-based ones you can take advantage of other tools such as grep (e.g. in conjunction with regular expressions) to further filter and analyze the results.
