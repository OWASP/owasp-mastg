---
title: Implicit intent to trigger internal app components.
platform: android
id: MASTG-TEST-0026
type: [dynamic]
weakness: MASWE-
---

## Overview

Android allows communication between components using intents, which are messaging objects used to request actions from other application components. Intents can be either explicit - targeting a specific component - or implicit, where the system determines the appropriate component based on the intent's action, data, or category. When an app declares an internal component, such as an Activity, with `android:exported="true"` and associates it with a `<intent-filter>`, it becomes accessible to external applications through implicit intents. This can pose a security risk if the component performs sensitive operations or trusts input from the intent without validation. An attacker could craft a malicious application to trigger these exported components and potentially manipulate application behaviour or extract sensitive information.

## Steps

1. Install the attacker app on a device @MASTG-TECH-0004.
2. Press the button to trigger the malicious intent.

## Observation

The attacker's application was able to successfully launch the VulnerableActivity using an crafted intent.

## Evaluation

The test fails due to the following exported activity being accessible via an implicit intent.
