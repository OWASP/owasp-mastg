---
title: Method Tracing
platform: android
---

In contrast to method profiling, which tells you how frequently a method is being called, method tracing helps you to also determine its input and output values. This technique can prove to be very useful when dealing with applications that have a big codebase and/or are obfuscated.

If you prefer a GUI-based approach you can use tools such as [RMS - Runtime Mobile Security](0x08a-Testing-Tools.md#RMS-Runtime-Mobile-Security) which enables a more visual experience as well as include several convenience [tracing options](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#3-hook-on-the-fly-classesmethods-and-trace-their-args-and-return-values).

If you prefer the command line, Frida offers a useful syntax to query Java classes and methods as well as Java method tracing support for frida-trace via `-j` (starting on frida-tools 8.0, Frida 12.10).

- In Frida scripts: e.g. `Java.enumerateMethods('*youtube*!on*')` uses globs to take all classes that include "youtube" as part of their name and enumerate all methods starting with "on".
- In frida-trace: e.g. `-j '*!*certificate*/isu'` triggers a case-insensitive query (`i`), including method signatures (`s`) and excluding system classes (`u`).

Refer to the [Release Notes for Frida 12.10](https://frida.re/news/2020/06/29/frida-12-10-released/ "Frida 12.10") for more details on this new feature. To learn more about all options for advanced usage, check the [documentation on the official Frida website](https://frida.re/docs/frida-trace/ "documentation").
