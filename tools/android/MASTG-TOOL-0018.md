---
title: jadx
platform: android
source: https://github.com/skylot/jadx
---

jadx (Dex to Java Decompiler) is a command line and [GUI tool](https://github.com/skylot/jadx/wiki/jadx-gui-features-overview "jadx gui features overview") for producing Java source code from Android DEX and APK files - <https://github.com/skylot/jadx>

## Decompiling via CLI

The @MASTG-APP-0003 app can be decompiled using `jadx` by specifying the output directory and the target APK:

```console
jadx -d decompiled UnCrackable-Level1.apk
```

## Opening an APK with jadx-gui

You can open an APK file either by launching `jadx-gui` and using the GUI, or by directly specifying the APK when launching jadx-gui:

```console
jadx-gui Uncrackable-Level1.apk
```

<img src="Images/Techniques/0017-jadxgui.png" width="800px" />
