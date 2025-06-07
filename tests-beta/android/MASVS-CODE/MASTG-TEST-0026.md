---
title: Implicit intent to trigger internal app components
platform: android
id: MASTG-TEST-0026
type: [dynamic]
weakness: MASWE-0083
---

## Overview

Android enables communication between its components through intents, which serve as messaging objects to request actions from other application components. Intents can be explicit, targeting a specific component, or implicit, where the system identifies the suitable component based on the intent's action, data, or category. When you declare an internal component, like an Activity, with `android:exported="true"` and link it to an `<intent-filter>`, it becomes available to external applications via implicit intents. This can introduce security vulnerabilities if the component handles sensitive tasks or accepts input from the intent without proper validation. An attacker might create a malicious app to activate these exported components, potentially altering application behavior or accessing sensitive data.

## Steps

1. Install the attacker app on a device @MASTG-TECH-0004.
2. Press the button to trigger the malicious intent.

## Observation

The attacker's application was able to successfully launch the VulnerableActivity using an crafted intent.

## Evaluation

The test fails due to the exported activity being accessible via an implicit intent.
