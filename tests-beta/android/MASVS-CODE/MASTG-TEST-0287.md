---
title: Implicit intent to trigger internal app components
platform: android
id: MASTG-TEST-0287
type: [static]
weakness: MASWE-0083
---

## Overview

Android enables communication between its components through intents, which serve as messaging objects to request actions from other application components. Intents can be explicit, targeting a specific component, or implicit, where the system identifies the suitable component based on the intent's action, data, or category. When a component such as an Activity is declared with `android:exported="true"` and includes an `<intent-filter>` with a custom action, it becomes accessible to external applications. If an app sends an implicit intent with sensitive data, and that intent can be intercepted by a malicious app, it results in a serious information disclosure vulnerability. Static analysis helps detect both the unsafe intent-sending code and the misconfigured exported component.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the `AndroidManifest.xml` file.

## Observation

The Semgrep output shows:

The `AndroidManifest.xml` file declares VulnerableActivity with `android:exported="true"` and an intent filter that matches the custom action `org.owasp.mastestapp.PROCESS_SENSITIVE_DATA`.

This indicates that internal app functionality can be triggered externally, and potentially misused or intercepted by untrusted apps.

## Evaluation

The test fails because the `AndroidManifest.xml` declares an exported activity with an `<intent-filter>` that uses a custom action. This configuration allows the component to be triggered by any external application using an implicit intent with the matching action.
