---
title: dependency-check
platform: generic
source: https://github.com/jeremylong/DependencyCheck
---

[Dependency-Check](https://github.com/jeremylong/DependencyCheck) is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies.

SCA tools will fail to scan an IPA or APK, as:

- **Transformed format**: The libraries are no longer in their original format but are part of the app binaries compiled code format.
- **Lack of metadata**: Information such as the library version or name is stripped or altered when building the mobile app.
- **Hash mismatch**: The transformation of dependencies during the mobile app build process changes the file's hash, so tools that rely on matching file hashes (like @MASTG-TOOL-0116) won’t work after the transformation.
