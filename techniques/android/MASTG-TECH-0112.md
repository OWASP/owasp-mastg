---
title: Reverse Engineering Flutter Applications
platform: android
---

Flutter is an open source UI SDK from Google for building natively compiled applications for mobile, web, and desktop from a single codebase. Dart, the programming language used in Flutter, is key to its functionality, offering language features and performance optimizations that enable efficient development of high-quality cross-platform apps.

A Dart snapshot is a pre-compiled representation of a Dart program that allows for faster startup times and efficient execution. Flutter application development focuses is on the AOT (Ahead-of-Time) snapshot, which is used in all Flutter mobile apps.

There are significant challenges in reverse engineering Dart AOT snapshots due to several factors:

1. **Distinctive Assembly Code**: The generated assembly code uses unique registers, calling conventions, and integer encoding, complicating analysis.
2. **Sequential Class Information**: Information about each class in the Dart AOT snapshot must be read sequentially, preventing random access and making it time-consuming to locate specific classes.
3. **Lack of Documentation**: The Dart snapshot format lacks comprehensive documentation and has evolved over time, adding to the complexity.
4. **Obfuscation and Optimization**: Flutter's build process may include [obfuscation](https://docs.flutter.dev/deployment/obfuscate) and optimization techniques that hinder reverse engineering efforts.

Because of these challenges, analyzing Flutter applications effectively requires specialized tools and methods.

## Using Blutter

To use @MASTG-TOOL-0116, you need to:

1. **Extract the APK**: Unpack the APK file and locate the libflutter.so file.
2. **Execute Blutter**: Run Blutter with the path to the libflutter.so file and specify an output directory.

```bash
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

Blutter generates several files:

- `asm/*`: Assembly files with symbols.
- `blutter_frida.js`: A Frida script template for instrumenting the app.
- `objs.txt`: A complete nested dump of objects from the object pool.
- `pp.txt`: All Dart objects in the object pool.

The assembly files in `asm/*` contain reconstructed functions with names, making it easier to trace the app's logic. Here's an excerpt of a `main` function:

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
