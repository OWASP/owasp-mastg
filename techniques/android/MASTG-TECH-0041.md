---
title: Library Injection
platform: android
---

In the previous section we learned about patching application code to assist in our analysis, but this approach has several limitations. For instance, you'd like to log everything that's being sent over the network without having to perform a MITM attack. For this you'd have to patch all possible calls to the network APIs, which can quickly become impractical when dealing with large applications. In addition, the fact that patching is unique to each application can also be considered a shortcoming, as this code cannot be easily reused.

Using library injection you can develop reusable libraries and inject them to different applications, effectively making them behave differently without having to modify their original source code. This is known as DLL injection on Windows (broadly used to modify and bypass anti-cheat mechanisms in games), `LD_PRELOAD` on Linux and `DYLD_INSERT_LIBRARIES` on macOS. On Android and iOS, a common example is using the Frida Gadget whenever Frida's so-called [Injected mode](https://frida.re/docs/modes/#injected "Frida Injected Mode") of operation isn't suitable (i.e. you cannot run the Frida server on the target device). In this situation, you can [inject the Gadget](https://frida.re/docs/gadget/ "Frida Gadget") library by using the same methods you're going to learn in this section.

Library injection is desirable in many situations such as:

- Performing process introspection (e.g. listing classes, tracing method calls, monitoring accessed files, monitoring network access, obtaining direct memory access).
- Supporting or replacing existing code with your own implementations (e.g. replace a function that should give random numbers).
- Introducing new features to an existing application.
- Debugging and fixing elusive runtime bugs on code for which you don't have the original source.
- Enable dynamic testing on a non-rooted device (e.g. with Frida).

In this section, we will learn about techniques for performing library injection on Android, which basically consist of patching the application code (smali or native) or alternatively using the `LD_PRELOAD` feature provided by the OS loader itself.

## Patching the Application's Smali Code

An Android application's decompiled smali code can be patched to introduce a call to `System.loadLibrary`. The following smali patch injects a library named libinject.so:

```default
const-string v0, "inject"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

Ideally you should insert the above code early in the [application lifecycle](https://developer.android.com/guide/components/activities/activity-lifecycle "Understand the Activity Lifecycle"), for instance in the `onCreate` method. It is important to remember to add the library libinject.so in the respective architecture folder (armeabi-v7a, arm64-v8a, x86) of the `lib` folder in the APK. Finally, you need to re-sign the application before using it.

A well-known use case of this technique is loading the Frida gadget to an application, especially while working on a non-rooted device (this is what [`objection patchapk`](https://github.com/sensepost/objection/wiki/Patching-Android-Applications "Patching Android Applications") basically does).

## Patching Application's Native Library

Many Android applications use native code in addition to Java code for various performance and security reasons. The native code is present in the form of ELF shared libraries. An ELF executable includes a list of shared libraries (dependencies) that are linked to the executable for it to function optimally. This list can be modified to insert an additional library to be injected into the process.

Modifying the ELF file structure manually to inject a library can be cumbersome and prone to errors. However, this task can be performed with relative ease using @MASTG-TOOL-0034 (Library to Instrument Executable Formats). Using it requires only a few lines of Python code as shown below:

```python
import lief

libnative = lief.parse("libnative.so")
libnative.add_library("libinject.so") # Injection!
libnative.write("libnative.so")
```

In the above example, libinject.so library is injected as a dependency of a native library (libnative.so), which the application already loads by default. Frida gadget can be injected into an application using this approach as explained in detail in [LIEF's documentation](https://lief.quarkslab.com/doc/latest/tutorials/09_frida_lief.html "LIEF's documentation - How to use frida on a non-rooted device"). As in the previous section, it is important to remember adding the library to the respective architecture `lib` folder in the APK and finally re-signing the application.

## Preloading Symbols

Above we looked into techniques which require some kind of modification of the application's code. A library can also be injected into a process using functionalities offered by the loader of the operating system. On Android, which is a Linux based OS, you can load an additional library by setting the `LD_PRELOAD` environment variable.

As the [ld.so man page](http://man7.org/linux/man-pages/man8/ld.so.8.html "LD.SO man page") states, symbols loaded from the library passed using `LD_PRELOAD` always get precedence, i.e. they are searched first by the loader while resolving the symbols, effectively overriding the original ones. This feature is often used to inspect the input parameters of some commonly used libc functions such as `fopen`, `read`, `write`, `strcmp`, etc., specially in obfuscated programs, where understanding their behavior may be challenging. Therefore, having an insight on which files are being opened or which strings are being compared may be very valuable. The key idea here is "function wrapping", meaning that you cannot patch system calls such as libc's `fopen`, but you can override (wrap) it including custom code that will, for instance, print the input parameters for you and still call the original `fopen` remaining transparent to the caller.

On Android, setting `LD_PRELOAD` is slightly different compared to other Linux distributions. If you recall from the "[Platform Overview](../../Document/0x05a-Platform-Overview.md#zygote "Platform Overview")" section, every application in Android is forked from Zygote, which is started very early during the Android boot-up. Thus, setting `LD_PRELOAD` on Zygote is not possible. As a workaround for this problem, Android supports the `setprop` (set property) functionality. Below you can see an example for an application with package name `com.foo.bar` (note the additional `wrap.` prefix):

```bash
setprop wrap.com.foo.bar LD_PRELOAD=/data/local/tmp/libpreload.so
```

> Please note that if the library to be preloaded does not have SELinux context assigned, from Android 5.0 (API level 21) onwards, you need to disable SELinux to make `LD_PRELOAD` work, which may require root.
