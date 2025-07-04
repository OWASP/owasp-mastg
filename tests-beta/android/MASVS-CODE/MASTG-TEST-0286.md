---
title: Implicit intent to intecept internal app components
platform: android
id: MASTG-TEST-0286
type: [dynamic]
profiles: [L1, L2]
weakness: MASWE-0083
---

## Overview

Android enables communication between its components through intents, which serve as messaging objects to request actions from other application components. Intents can be explicit, targeting a specific component, or implicit, where the system identifies the suitable component based on the intent's action, data, or category. When you declare an internal component, like an Activity, with `android:exported="true"` and link it to an `<intent-filter>`, it becomes available to external applications via implicit intents. This can introduce security vulnerabilities if the component handles sensitive tasks or accepts input from the intent without proper validation. An attacker might create a malicious app to activate these exported components, potentially altering application behavior or accessing sensitive data.

## Steps

1. Install the vulnerable app on the device.

2. Install the attacker app on the device @MASTG-TECH-0004.

3. Launch the vulnerable app to trigger the implicit intent from vulnerable app.

## Observation

The attacker's application was able to successfully launch the VulnerableActivity using an crafted intent and receive sensitive information.

## Evaluation

The test fails due to the exported activity being accessible via an implicit intent.
