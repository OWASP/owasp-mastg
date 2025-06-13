---
title: Apktool
platform: android
source: https://github.com/iBotPeaches/Apktool
---

[Apktool](https://github.com/iBotPeaches/Apktool) is used to unpack Android app packages (APKs). Simply unzipping APKs with the standard `unzip` utility leaves some files unreadable. `AndroidManifest.xml` is encoded into binary XML format which isn't readable with a text editor. Also, the app resources are still packaged into a single archive file.

When run with default command line flags, apktool automatically decodes the Android Manifest file to text-based XML format and extracts the file resources (it also disassembles the .DEX files to smali code - a feature that we'll revisit later in this book).

Among the unpacked files you can usually find (after running `apktool d base.apk`):

- AndroidManifest.xml: The decoded Android Manifest file, which can be opened and edited in a text editor.
- apktool.yml: file containing information about the output of apktool
- original: folder containing the MANIFEST.MF file, which contains information about the files contained in the JAR file
- res: directory containing the app's resources
- smali: directory containing the disassembled Dalvik bytecode.

You can also use apktool to repackage decoded resources back to binary APK/JAR. See the techniques @MASTG-TECH-0007 and @MASTG-TECH-0039 for more information and practical examples.
