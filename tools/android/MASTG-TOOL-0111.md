---
title: Blutter
platform: android
source: https://github.com/worawit/blutter
---

[Blutter](https://github.com/worawit/blutter) is an open-source tool created to support the reverse engineering of Flutter applications. Unlike other Flutter tools, Blutter parses the libapp.so file locally, without requiring you to run the app on a device. The tool is compatible Linux, Windows, and macOS, but can only analyse Android ARM64 apps. Blutter is capable of extracting and analyzing Dart objects and it can generate Frida scripts for further analysis.

This tool does require a specific environment to work, which can be found [here](https://github.com/worawit/blutter?tab=readme-ov-file#environment-setup).If you don’t want to setup the environment here is the docker support for the blutter tool.

Use the apktool to Extract "lib" directory from apk file.

```bash
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

Reference:
[B(l)utter – Reversing Flutter Applications](https://www.youtube.com/watch?v=EU3KOzNkCdI)
