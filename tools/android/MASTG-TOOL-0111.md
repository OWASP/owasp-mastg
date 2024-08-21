---
title: Blutter
platform: android
source: https://github.com/worawit/blutter
---

[Blutter](https://github.com/worawit/blutter) is an open-source tool created to support the reverse engineering of Flutter applications by compiling the Dart AOT Runtime. It targets the lib files found in decompiled apks and is compatible with the latest versions of Dart. It makes use of an advanced C++20 formatting library. The tool is compatible with Linux, Windows, and macOS operating systems. Blutter is capable of extracting and analyzing Dart objects and can generate Frida scripts for further analysis. It automatically compiles any required Dart versions that are not already installed.

This tool does require a specific environment to work, which can be found [here](https://github.com/worawit/blutter?tab=readme-ov-file#environment-setup).If you don’t want to setup the environment here is the docker support for the blutter tool.

Use the apktool to Extract "lib" directory from apk file.

```bash
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

Reference:
[B(l)utter – Reversing Flutter Applications](https://www.youtube.com/watch?v=EU3KOzNkCdI)
