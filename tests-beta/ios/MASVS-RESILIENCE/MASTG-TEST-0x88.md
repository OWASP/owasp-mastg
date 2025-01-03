---
platform: ios
title: Runtime Use of Jailbreak Detection Techniques
id: MASTG-TEST-0x88
type: [dynamic]
weakness: MASWE-0097
---

## Overview

The test verifies that a mobile application can identify if the iOS device it is running on a jailbroken device. Jailbreaking removes built-in security restrictions on the device, potentially exposing sensitive information and increasing the risk of unauthorized access.

## Steps

1. Run a dynamic analysis using [automated jailbreak detection bypass tool](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#automated-jailbreak-detection-bypass) such as @MASTG-TOOL-0038 on the binary.
2. Use @MASTG-TOOL-0073 on the binary for [manual jailbreak detection bypass](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#manual-jailbreak-detection-bypass) to check for common jailbreak detection such as [file permissions, protocol handlers and file directories](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#common-jailbreak-detection-checks).

## Observation

The output shows that the list of jailbreak detection checks has been successfully bypassed.

## Evaluation

The test fails if jailbreak detection is disabled.
