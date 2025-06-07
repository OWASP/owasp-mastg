---
platform: ios
title: Jailbreak Detection in Code
id: MASTG-TEST-0240
type: [dynamic]
weakness: MASWE-0097
false_negative_prone: true
profiles: [R]
---

## Overview

The test verifies that a mobile app can detect if the iOS device it is running on is jailbroken. It does so by statically analyzing the app binary for [common jailbreak detection checks](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#common-jailbreak-detection-checks). For example, the app may check for the presence of a third-party app store (e.g. Sileo, Zebra, ...), or for the presence of certain files or directories that are indicative of a jailbroken device.

The limitations of static analysis should be considered. It is possible that the app uses more sophisticated jailbreak detection techniques that are not detected by the used tool. In such cases, careful manual reverse engineering and deobfuscation are required to identify the jailbreak detection checks.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary looking for common jailbreak detection checks.

## Observation

The output should include any instances of common jailbreak detection checks in the app binary.

## Evaluation

The test passes if jailbreak detection is implemented.

The test fails if jailbreak detection is not implemented. However, note that this test is not exhaustive and may not detect all jailbreak detection checks. Manual reverse engineering and deobfuscation may be required to identify more sophisticated jailbreak detection checks.
