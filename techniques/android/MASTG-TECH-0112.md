---
title: Reverse Engineering Flutter Applications
platform: android
---

Flutter is an open-source UI SDK by Google for building natively compiled applications across mobile, web, and desktop from a single codebase. Dart, the programming language used in Flutter, is key to its functionality, offering language features and performance optimizations that enable efficient development of high-quality cross-platform apps.

A Dart snapshot is a pre-compiled representation of a Dart program that allows for faster startup times and efficient execution. In Flutter application development, the primary focus is on the AOT (Ahead-of-Time) snapshot, as it is used in all Flutter mobile applications.

There are significant challenges in reverse engineering Dart AOT snapshots due to several factors. The generated assembly code uses distinctive features, including specific registers, calling conventions, and integer encoding, making analysis more complex. In addition, information about each class in the snapshot must be read
sequentially, preventing random access and requiring engineers to sift through potentially irrelevant classes to locate the one of interest. Moreover, the format lacks documentation and has evolved considerably over time, further complicating the reverse engineering process. These unique characteristics of the Flutter framework make reverse engineering Flutter applications particularly difficult.

Currently, a tool exists that can efficiently reverse engineer Flutter applications. One such tool is called [Blutter](https://github.com/worawit/blutter) which can be directly downloaded from Github.

## Reversing Flutter with Blutter

Executing the Blutter program is straightforward and can be done with a single command, as shown below. The user simply needs to specify the directory containing the `libflutter.so` file and the desired output directory. Then the "lib" directory will be extracted from the APK file.

```bash
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

The output generated from executing Blutter consists of

- asm/* libapp assemblies with symbols
- blutter_frida.js the Frida script template for the target application
- objs.txt complete (nested) dump of Object from Object Pool
- pp.txt all Dart objects in Object Pool

```bash
┌──(kali㉿kali)-[~/Desktop/Dummy_Output]
└─$ ls -l 
total 3084
drwxrwxr-x   117 kali kali   4096    Oct 15 05:51 asm
-rw-r--r--   1   kali kali   397168  Oct 15 05:51 blutter_frida.js
drwxrwxr-x   2   kali kali   4096    Oct 15 05:51 ida_script
-rw-rw-r--   1   kali kali   740945  Oct 15 05:51 objs.txt
-rw-rw-r--   1   kali kali   2009647 Oct 15 05:51 pp.txt
```

Below is an assembly example of a main function. The assembly generated from executing Blutter contains a function name ready to be used for analysis.

```plaintext
  static _ main(/* No info */) async {
    // ** addr: 0x5961e0, size: 0x230
    // 0x5961e0: EnterFrame
    //     0x5961e0: stp             fp, lr, [SP, #-0x10]!
    //     0x5961e4: mov             fp, SP
    // 0x5961e8: AllocStack(0x28)
    //     0x5961e8: sub             SP, SP, #0x28
    // 0x5961ec: SetupParameters()
    //     0x5961ec: stur            NULL, [fp, #-8]
    // 0x5961f0: CheckStackOverflow
    //     0x5961f0: ldr             x16, [THR, #0x38]  ; THR::stack_limit
    //     0x5961f4: cmp             SP, x16
    //     0x5961f8: b.ls            #0x596400
    // 0x5961fc: InitAsync() -> Future<void?>
    //     0x5961fc: ldr             x0, [PP, #0x80]  ; [pp+0x80] TypeArguments: <void?>
    //     0x596200: bl              #0x3a5d48
    // 0x596204: r0 = ensureInitialized()
    //     0x596204: bl              #0x570d8c  ; [package:flutter/src/widgets/binding.dart] WidgetsFlutterBinding::ensureInitialized
    // 0x596208: r0 = init()
    //     0x596208: bl              #0x59a98c  ; [package:get_secure_storage/src/storage_impl.dart] GetSecureStorage::init
    // 0x59620c: mov             x1, x0
    // 0x596210: stur            x1, [fp, #-0x10]
    // 0x596214: r0 = Await()
```
