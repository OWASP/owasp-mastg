---
platform: android
title: Implicit Intent Hijacking
id: MASTG-DEMO-0043
code: [kotlin]
test: MASTG-TEST-0027
---

### Sample

The code snippet shows that an implicit intent is used to launch an activity using Intent without specifying the target component. This could allow malicious applications to hijack the intent.

{{ ../MASTG-DEMO-0042/MastgTest_reversed.java # ../MASTG-DEMO-0042/AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the manifest file and code.

{{ ../../../../rules/mastg-android-implicit-intent-start-activity.yml }}

{{ ../../../../rules/mastg-android-exported-activity.yml }}

{{ run.sh }}

### Observation

The first semgrep output shows that the implicit Intent usage in the code (e.g., `Intent.setAction(...)`, then starts activity with `startActivity`.

The second semgrep output shows that `org.owasp.mastestapp.VulnerableActivity` is an exported activity declared in the `AndroidManifest.xml`. It contains an `<intent-filter>` block that registers a custom action.

### Evaluation

The test fails because of presence of both an implicit intent usage in the code and an exported activity with a matching action confirms a vulnerability in the component that can be exploited by attacker application.
