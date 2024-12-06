---
title: cdxgen
platform: generic
source: https://github.com/CycloneDX/cdxgen
---

[cdxgen](https://cyclonedx.github.io/cdxgen/) can generate Software Bill of Materials (SBOM) for most applications and container images with a single command. It supports SwiftPM for iOS and Maven for Android. The generated SBOM can then be submitted to @MASTG-TOOL-0117 for analysis.

The creation of an SBOM out of an Android App (APK or AAB) is supported, but limited. Due to stripping out meta-information of the libraries used in an app, a SBOM created ouf of an Android app will always be incomplete.

It is therefore recommended to execute `cdxgen` in the Android App project folder to create a complete SBOM.
