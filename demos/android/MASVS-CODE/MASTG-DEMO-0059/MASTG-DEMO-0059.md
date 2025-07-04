---
platform: android
title: Implicit intent to trigger internal app components
id: MASTG-DEMO-0059
code: [kotlin]
test: MASTG-TEST-0287
---

### Sample

The manifest snippet outlines an exported activity featuring an `<intent-filter>` with a unique action. This allows the component to be reachable by any application on the device that registers the identical intent action, which could allow a malicious app to capture such intents.

{{ ../MASTG-DEMO-0058/AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the manifest file and code.

{{ ../../../../rules/mastg-android-custom-intent-filter-intercept.yml }}

{{ run.sh }}

### Observation

Semgrep identifies that the `org.owasp.mastestapp.VulnerableActivity` component is both:

- Marked as `android:exported="true"`.

- Declares an `<intent-filter>` with a custom action `org.owasp.mastestapp.PROCESS_SENSITIVE_DATA`.

This configuration allows any third-party app to register the same action and receive the implicit intent, enabling potential hijacking of sensitive data.

### Evaluation

The test fails because the exported activity can be accessed through a custom implicit action. This exposes internal functionality to untrusted apps.
