---
title: Implicit intent to trigger internal app components
platform: android
id: MASTG-TEST-0027
type: [static]
weakness: MASWE-0083
---

## Overview

Android enables communication between its components through intents, which serve as messaging objects to request actions from other application components. Intents can be explicit, targeting a specific component, or implicit, where the system identifies the suitable component based on the intent's action, data, or category. When you declare an internal component, like an Activity, with `android:exported="true"` and link it to an `<intent-filter>`, it becomes available to external applications via implicit intents. This can introduce security vulnerabilities if the component handles sensitive tasks or accepts input from the intent without proper validation. An attacker might create a malicious app to activate these exported components, potentially altering application behavior or accessing sensitive data.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and `AndroidManifest.xml` file.

## Observation

The code uses an implicit intent by setting an action via `Intent.setAction()` and launching it with `startActivity()`. Also, `AndroidManifest.xml` declares an exported activity with an intent filter that matches the custom action.

## Evaluation

The test fails due to the exported activity being accessible via an implicit intent.
