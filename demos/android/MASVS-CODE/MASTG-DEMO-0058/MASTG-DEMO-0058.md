---
platform: android
title: Implicit Intent Hijacking with same custom intent filter
id: MASTG-DEMO-0058
code: [kotlin]
test: MASTG-TEST-0286
---

### Sample

The code snippet below demonstrates the use of an implicit intent with sensitive data and a custom action, without specifying a target component.

{{ MastgTest.kt # MastgTest_reversed.java }}

### MastgTestAttacker.kt

The attacker app has an exported activity that includes a corresponding `<intent-filter>` which registers the identical custom action, enabling it to capture the implicit intent sent out by the victim app.

{{ MastgTestAttacker.kt }}

### MastgTestInternalData.kt

A component within the vulnerable app originally intended to process sensitive data, but is exposed via an implicit intent mechanism. Although not explicitly targeted, it can be hijacked by any app that claims to handle the same action.

{{ MastgTestInternalData.kt }}

### Steps

1. Install the attacker app on a device using @MASTG-TECH-0004.
2. On the vulnerable app, click on start to start the test.

{{ MastgTestAttacker.kt }}
{{ AndroidManifestAttacker_app.xml }}

### Observation

The attacker app successfully intercepted the intent containing sensitive extras such as tokens, API keys, and credentials. This confirms that any app declaring a matching `<intent-filter>` can receive these values without restriction.

### Evaluation

The test fails due to the use of an exported activity (VulnerableActivity) that includes an intent filter with a custom action. Combined with the implicit intent in `MastgTest.kt`, this creates a vulnerable pattern where sensitive data is transmitted to an untrusted receiver.
