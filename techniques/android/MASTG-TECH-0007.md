---
title: Exploring the App Package
platform: android
---

Once you have collected the package name of the application you want to target, you'll want to start gathering information about it. First, retrieve the APK as explained in @MASTG-TECH-0003.

APK files are actually ZIP files that can be unpacked using a standard decompression utility such as `unzip`. However, we recommend using @MASTG-TOOL-0011 which additionally decodes the AndroidManifest.xml and disassembles the app binaries (classes.dex) to smali code:

```bash
$ apktool d UnCrackable-Level3.apk
$ tree
.
├── AndroidManifest.xml
├── apktool.yml
├── lib
├── original
│   ├── AndroidManifest.xml
│   └── META-INF
│       ├── CERT.RSA
│       ├── CERT.SF
│       └── MANIFEST.MF
├── res
...
└── smali
```

The following files are unpacked:

- AndroidManifest.xml: contains the definition of the app's package name, target and minimum [API level](https://developer.android.com/guide/topics/manifest/uses-sdk-element#ApiLevels "API Levels"), app configuration, app components, permissions, etc.
- original/META-INF: contains the app's metadata
    - MANIFEST.MF: stores hashes of the app resources
    - CERT.RSA: the app's certificate(s)
    - CERT.SF: list of resources and the SHA-1 digest of the corresponding lines in the MANIFEST.MF file
- assets: directory containing app assets (files used within the Android app, such as XML files, JavaScript files, and pictures), which the [AssetManager](https://developer.android.com/reference/android/content/res/AssetManager) can retrieve
- classes.dex: classes compiled in the DEX file format, that Dalvik virtual machine/Android Runtime can process. DEX is Java bytecode for the Dalvik Virtual Machine. It is optimized for small devices
- lib: directory containing third-party libraries that are part of the APK
- res: directory containing resources that haven't been compiled into resources.arsc
- resources.arsc: file containing precompiled resources, such as XML files for the layout

As unzipping with the standard `unzip` utility leaves some files such as the `AndroidManifest.xml` unreadable, it's better to unpack the APK using @MASTG-TOOL-0011.

```bash
$ ls -alh
total 32
drwxr-xr-x    9 sven  staff   306B Dec  5 16:29 .
drwxr-xr-x    5 sven  staff   170B Dec  5 16:29 ..
-rw-r--r--    1 sven  staff    10K Dec  5 16:29 AndroidManifest.xml
-rw-r--r--    1 sven  staff   401B Dec  5 16:29 apktool.yml
drwxr-xr-x    6 sven  staff   204B Dec  5 16:29 assets
drwxr-xr-x    3 sven  staff   102B Dec  5 16:29 lib
drwxr-xr-x    4 sven  staff   136B Dec  5 16:29 original
drwxr-xr-x  131 sven  staff   4.3K Dec  5 16:29 res
drwxr-xr-x    9 sven  staff   306B Dec  5 16:29 smali
```

## The Android Manifest

The Android Manifest is the main source of information, it includes a lot of interesting information such as the package name, the permissions, app components, etc.

Here's a non-exhaustive list of some info and the corresponding keywords that you can easily search for in the Android Manifest by just inspecting the file or by using `grep -i <keyword> AndroidManifest.xml`:

- App permissions: `permission` (see "[Android Platform APIs](../../Document/0x05h-Testing-Platform-Interaction.md "Testing Platform Interaction")")
- Backup allowance: `android:allowBackup` (see "[Data Storage on Android](../../Document/0x05d-Testing-Data-Storage.md "Testing Data Storage)"))
- App components: `activity`, `service`, `provider`, `receiver` (see "[Android Platform APIs](../../Document/0x05h-Testing-Platform-Interaction.md "Testing Platform Interaction")" and "[Data Storage on Android](../../Document/0x05d-Testing-Data-Storage.md "Testing Data Storage)"))
- Debuggable flag: `debuggable` (see "[Code Quality and Build Settings of Android Apps](../../Document/0x05i-Testing-Code-Quality-and-Build-Settings.md "Testing Code Quality and Build Settings")")

Please refer to the mentioned chapters to learn more about how to test each of these points.

## App Binary

The app binary (`classes.dex`) can be found in the root directory of the app package. It is a so-called DEX (Dalvik Executable) file that contains compiled Java code. Due to its nature, after applying some conversions you'll be able to use a decompiler to produce Java code. We've also seen the folder `smali` that was obtained after we run apktool. This contains the disassembled Dalvik bytecode in an intermediate language called smali, which is a human-readable representation of the Dalvik executable.

Refer to @MASTG-TECH-0023 for more information about how to reverse engineer DEX files.

## Compiled App Binary

In some cases it might be useful to retrieve the compiled app binary (.odex).

First get the path to the app's data directory:

```bash
adb shell pm path com.example.myapplication
package:/data/app/~~DEMFPZh7R4qfUwwwh1czYA==/com.example.myapplication-pOslqiQkJclb_1Vk9-WAXg==/base.apk
```

Remove the `/base.apk` part, add `/oat/arm64/base.odex` and use the resulting path to pull the base.odex from the device:

```bash
adb root
adb pull /data/app/~~DEMFPZh7R4qfUwwwh1czYA==/com.example.myapplication-pOslqiQkJclb_1Vk9-WAXg==/oat/arm64/base.odex
```

Note that the exact directory will be different based on your Android version. If the `/oat/arm64/base.odex` file can't be found, manually search in the directory returned by `pm path`.

## Native Libraries

You can inspect the `lib` folder in the APK:

```bash
$ ls -1 lib/armeabi/
libdatabase_sqlcipher.so
libnative.so
libsqlcipher_android.so
libstlport_shared.so
```

or from the device with objection:

```bash
...g.vp.owasp_mobile.omtg_android on (google: 8.1.0) [usb] # ls lib
Type    ...  Name
------  ...  ------------------------
File    ...  libnative.so
File    ...  libdatabase_sqlcipher.so
File    ...  libstlport_shared.so
File    ...  libsqlcipher_android.so
```

For now this is all information you can get about the native libraries unless you start reverse engineering them, which is done using a different approach than the one used to reverse the app binary as this code cannot be decompiled but only disassembled. Refer to @MASTG-TECH-0024 for more information about how to reverse engineer these libraries.

## Other App Resources

It is normally worth taking a look at the rest of the resources and files that you may find in the root folder of the APK as some times they contain additional goodies like key stores, encrypted databases, certificates, etc.
