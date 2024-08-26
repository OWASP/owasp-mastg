---
title: uber-apk-signer
platform: android
source: https://github.com/patrickfav/uber-apk-signer
---

A tool that helps to sign, [zip align](https://developer.android.com/studio/command-line/zipalign.html) and verify one or more Android application packages (APKs) with either debug or provided release certificates. It supports v1, v2, [v3](https://source.android.com/security/apksigning/v3) and [v4](https://source.android.com/security/apksigning/v4) Android signing schemes. Easy and convenient debug signing with embedded debug keystore. Automatically verifies signature and zip alignment after signing.

Download the jar from the [latest release](https://github.com/patrickfav/uber-apk-signer/releases/latest) and run:

```bash
$ java -jar uber-apk-signer.jar --apks </path/to/apks>
```

Demo:

[![asciicast](https://asciinema.org/a/91092.png)](https://asciinema.org/a/91092)

For more information go to the [GitHub repository](https://github.com/patrickfav/uber-apk-signer).
