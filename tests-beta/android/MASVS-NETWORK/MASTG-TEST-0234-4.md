---
title: Correct use of SSL error handling for webviews
platform: android
id: MASTG-TEST-0234-4
type: [static]
weakness: MASWE-0052
---

## Overview

Inside `apktool.xml`, in the root property, if `targetSdkVersion` is less then 24, the use of certificates imported on the user's behalf is allowed.

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018). You can also use @MASTG-TECH-0117 to extract the `AndroidMnaifest.xml` from the apk.
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `targetSdkVersion`.
3- Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `<certificates src="user" />`.

## Observation

You will find that the `targetSdkVersion` within `apktool.xml` is less then 24. This indicate that the targetSdk version set in the `AndroidManifest.xml` also is 23. This allows for certificates to be imported and used on the user's behalf which would allow for the use of certificates with an insecure CA. Please keep in mind that this property could be overridden by `build.gradle.kts` by setting the `targetSdk` version there which is more common then having it defined in `AndroidManifest.xml`. Still the `apktool.xml` should reflect this. You will also see that the `network_security_config.xml` contains `<certificates src="user" />` which confirms that certificates imported on the user's behalf is in use.

## Evaluation

The test case fails if `platformBuildVersionCode` is less then 24 and `<certificates src="user" />` has been defined.
