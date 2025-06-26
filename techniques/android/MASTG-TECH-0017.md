---
title: Decompiling Java Code
platform: android
---

When reverse-engineering an Android application, make sure to always identify all locations of interest in regards to application logic and use the correct techniques to reverse-engineer them. In this technique we'll focus on the DEX bytecode, which is stored in one or more `classes<x>.dex` files in the main directory of the APK. But Android applications may also contain code in other files which will be interpreted by either a system component (e.g. a `WebView`) or packaged native libraries.

Decompiling DEX bytecode into Java is typically an easy process and many decompilers exist that can deliver code that is near-identical to the original source code. However, some information is inherently always lost during compilation, so the retrieved code will never be a perfect match. However, if the code has been purposefully obfuscated (or some tool-breaking anti-decompilation tricks have been applied), the reverse engineering process may be very time-consuming and unproductive. This also applies to applications that contain native code. They can still be reverse engineered, but the process cannot be trivially automated and requires knowledge of low-level details.

While DEX bytecode and Java bytecode are not the same, they can be converted into each other. As a result, Android applications can be decompiled using Java decompilers by first converting the `.dex` files into `.jar` files and then decompiling the `.jar` files. Since one application can have multiple `.dex`, this is a tedious process, and luckily many decompilers have native support for `.apk` files, thereby taking care of this process for you. Some decompilers also work directly on DEX bytecode, rather than converting it into Java bytecode first.

Due to the long legacy of Java applications, many decompilers can be used to decompile Android applications. While some very strong commercial Android decompilers exist, there are free decompilers which rival commercial decompilers in many aspects. The most popular free decompiler is @MASTG-TOOL-0018, which is actively developed. If jadx fails to decompile a part of the code, the easiest alternative is @MASTG-TOOL-0014, which combines six different decompilers in one application ([JD-GUI](http://java-decompiler.github.io/), [Procyon](https://github.com/mstrobel/procyon), [CFR](https://www.benf.org/other/cfr/), [Fernflower](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine), [Krakatau](https://github.com/Storyyeller/Krakatau) and [JADX-Core](https://github.com/skylot/jadx)). Both of these decompilers have native support for `.apk` files, and while it may seem that bytecodeviewer is the better choice, jadx has many more UI features that offer a much more pleasant user experience than bytecodeviewer.

!!! warning

    Decompilation can always fail, either due to intentional manipulation of the `.dex` files, or simply due to bugs in the decompilers. If all decompilers fail, you can always fall back to @MASTG-TECH-0016.

Let's take a look at the decompiled version of @MASTG-APP-0003 in a few different decompilers:

## Using jadx-gui

You can open an APK file either by launching `jadx-gui` and using the GUI, or by directly specifying the APK when launching jadx-gui:

```console
jadx-gui Uncrackable-Level1.apk
```

<img src="Images/Techniques/0017-jadxgui.png" width="800px" />

Jadx-gui usually does very well when decompiling Android applications. If decompilation is unsuccessful, it also supports multiple fallback modes which can be toggled at the bottom of the pane (SMALI, Simple, Fallback)

## Using jadx

In addition to opening the binary with jadx-gui, it's also possible to use jadx's core to decompile the code to the filesystem. Afterwards, you can use your favorite code editor to examine the code:

```console
jadx -d decompiled UnCrackable-Level1.apk
```

It's possible to specify which class to decompile, rather than decompile the entire application. This can be done with the `--single-class` argument:

```console
jadx --single-class sg.vantagepoint.uncrackable1.MainActivity UnCrackable-Level1.apk 
INFO  - loading ...
INFO  - Saving class 'sg.vantagepoint.uncrackable1.MainActivity' to file '/home/owasp/UnCrackable-Level1/sources/sg/vantagepoint/uncrackable1/MainActivity.java'
INFO  - done
```

Jadx also has a feature that allows you to create a gradle project from the decompiled code. This gradle project can then be opened with @MASTG-TOOL-0007. Note that you won't be able to actually compile the application due to the loss of information during the original compilation, but you can still use Android Studio's powerful IDE features to analyze the decompiled code.

```console
jadx -d decompiled -e UnCrackable-Level1.apk
```

## Using Bytecodeviewer

<img src="Images/Techniques/0017-bytecodeviewer.png" width="800px" />

Bytecodeviewer can show different decompilers side by side. In the example above, Fernflower and CFR are shown. Even though the code is equivalent, there are differences between the two decompilation results. For example, CFR tends to use available type information when naming variables, while Fernflower simply uses `var{index}`.

See the section @MASTG-TECH-0023 to learn how to proceed when inspecting the decompiled Java code.
