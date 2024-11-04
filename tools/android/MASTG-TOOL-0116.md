---
title: Blutter
platform: android
hosts:
- linux
- windows
- macos
source: https://github.com/worawit/blutter
---

[Blutter](https://github.com/worawit/blutter) is an open-source tool created to support the reverse engineering of Flutter applications. Unlike other Flutter tools, Blutter parses the libapp.so file statically, without requiring you to run the app on a device. Blutter can:

- Extract and analyze Dart objects
- Provide annotations for instructions, including function names or pool objects where applicable
- Generate Frida scripts for further analysis

This tool requires a specific environment to function, which is explained in the [setup instructions](https://github.com/worawit/blutter?tab=readme-ov-file#environment-setup). Alternatively, a [convenient Docker file can be found in a PR](https://github.com/worawit/blutter/pull/50).

More information is available in the [B(l)utter – Reversing Flutter Applications presentation](https://www.youtube.com/watch?v=EU3KOzNkCdI).
