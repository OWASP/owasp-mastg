---
title: Missing Certificate Pinning in Code
platform: android
id: MASTG-TEST-0240
type: [static]
weakness: MASWE-0047
---

## Overview

Apps can configure certificate pinning using the [Network Security Configuration]("../../../Document/0x05g-Testing-Network-Communication.md#certificate-pinning"). For each domain, one or multiple digests can be pinned.

Certificate pinning can also be done manually in the code. Depending on the used technologies, this can be done for example by:

- Pinning a certificate with a custom `TrustManager`,
- configuring the used third party networking libraries to pin certificates,
- use plugins to achieve certificate pinning for hybrid apps.

Chapter [Certificate pinning without Android Network Security Configuration]("../../../Document/0x05g-Testing-Network-Communication.md#certificate-pinning-without-android-network-security-configuration") explains in more detail how this can be achieved in the app.

The goal of this test is to check if any certificate pinning exists.

!!! note "Limitations"
    Since there are many different ways to achieve certificate pinning in the code, checking statically if the application performs pinning might not reveal all such locations. To make sure certificates are pinned for all relevant connections, additional dynamic analysis can be performed.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the AndroidManifest.xml, and check if a `networkSecurityConfig` is set in the `<application>` tag. If yes, inspect the referenced file, and all domains which have a pinned certificate.
3. Run a static analysis tool such as @MASTG-TOOL-0011 or @MASTG-TOOL-0018 on the code and look for APIs or configurations performing certificate pinning (see above). Extract all domains for which the certificates are pinned.

## Observation

The output should contain a list of domains which enable certificate pinning.

## Evaluation

The test case fails if any relevant domain does not enable certificate pinning.
