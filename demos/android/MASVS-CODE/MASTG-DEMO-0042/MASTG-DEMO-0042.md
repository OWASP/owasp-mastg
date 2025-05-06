---
platform: android
title: Implicit Intent Hijacking
id: MASTG-DEMO-0042
code: [kotlin]
test: MASTG-TEST-0026
---

### Sample

The code snippet shows that an implicit intent is being used to launch an activity using Intent without specifying the target component. This may allow malicious applications to hijack the intent.

{{ MastgTest.kt # MastgTest_reversed.java }}

### MastgTestAttacker.kt

The code includes an application code that demonstrates how an attacker could exploit this configuration to launch internal activities or inject malicious data by sending crafted intents.

{{ MastgTestAttacker.kt }}

### VulnerableActivity.kt

A sample internal component of the application, which contains any sensitive data.

{{ VulnerableActivity.kt }}

### Steps

1. Install the attacker app on a device using @MASTG-TECH-0004.
2. Press the button to trigger the malicious intent.

### Observation

The output shows that the attacker's application was able to successfully launch the target application's internal VulnerableActivity using implicit intent. This confirms that the activity was exported and could be reached without explicit targeting.

### Evaluation

The test fails due to the following exported activity being accessible via an implicit intent:

- The `VulnerableActivity` is declared with `android:exported="true"` and includes an `<intent-filter>`, which allows it to be triggered by any external application without requiring explicit targeting or permissions. This confirms that internal components intended for use only within the app can be exposed and misused if not properly secured.
