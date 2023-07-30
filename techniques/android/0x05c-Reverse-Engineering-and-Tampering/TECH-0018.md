---
title: Method Tracing
platform: android
---

In contrast to method profiling, which tells you how frequently a method is being called, method tracing helps you to also determine its input and output values. This technique can prove to be very useful when dealing with applications that have a big codebase and/or are obfuscated.

As we will discuss shortly in the next section, `frida-trace` offers out-of-the-box support for Android/iOS native code tracing and iOS high level method tracing. If you prefer a GUI-based approach you can use tools such as [RMS - Runtime Mobile Security](0x08a-Testing-Tools.md#RMS-Runtime-Mobile-Security) which enables a more visual experience as well as include several convenience [tracing options](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#3-hook-on-the-fly-classesmethods-and-trace-their-args-and-return-values).
