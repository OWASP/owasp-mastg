---
title: blint
platform: android
source: https://github.com/owasp-dep-scan/blint
---

[BLint](https://github.com/owasp-dep-scan/blint) is a Binary Linter that checks the security properties and capabilities of an executable. Since version 2, `blint` can generate Software Bill-of-Materials (SBOM) for supported binaries, which includes Android (APK and AAB), but not iOS (IPA) apps.

The creation of an SBOM out of an Android App (APK or AAB) is supported, but [limited](https://github.com/owasp-dep-scan/blint/issues/119). Due to stripping out meta-information of the libraries used in an app, a SBOM created ouf of an Android app will always be incomplete.

BLint can be a choice in a black-box security assessment, but other tools should be preferred during a grey/white-box test, like:

- @MASTG-TOOL-0131
- @MASTG-TOOL-0132
- @MASTG-TOOL-0134
