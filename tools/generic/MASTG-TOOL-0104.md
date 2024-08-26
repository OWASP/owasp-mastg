---
title: hermes-dec
platform: generic
source: https://github.com/P1sec/hermes-dec/
---

[Hermes-dec](https://github.com/P1sec/hermes-dec/) is a tool for reverse-engineering compiled [hermes](https://reactnative.dev/docs/hermes) bytecode for both Android and iOS apps. It supports decompilation and disassembly of [Hermes VM bytecode (HBC)](https://lucasbaizer2.github.io/hasmer/hasm/instruction-docs/hbc86.html) format, typically seen in apps developed in [React Native](https://reactnative.dev/).

If you encounter either of the following files during static analysis, hermes-dec provides a way to recover a legible version of the file's contents:

- index.android.bundle
- main.jsbundle

Use `file` to check the type and confirm you are dealing with actual Hermes bytecode:

```bash
$ file main.jsbundle
main.jsbundle: Hermes JavaScript bytecode, version 90
```

If instead you see that it's a plain text file, it can be opened with any text editor and hermes-dec isn't needed:

```bash
$ file main.jsbundle
main.jsbundle: Unicode text, UTF-8 text
```

You can try using hermes-dec in situations where you are doing static analysis on a React Native mobile app, and [react-native-decompiler](https://github.com/numandev1/react-native-decompiler) fails.
