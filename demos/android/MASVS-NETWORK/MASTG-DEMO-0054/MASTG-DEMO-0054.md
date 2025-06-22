---
platform: android
title: Use of a TrustManager that Does Not Validate Certificate Chains
id: MASTG-DEMO-0054
code: [kotlin]
test: MSTG-TEST-0282
---

### Sample

This sample connects to <https://tlsexpired.no>, which has an expired certificate, to demonstrate the insecure use of a custom `TrustManager` that ignores certificate chain validity. It does this by overriding the `checkServerTrusted(...)` method and leaving it empty, which effectively disables certificate validation.

{{ MastgTest.kt # MastgTest_reversed.java }}

If the app wouldn't use the insecure `TrustManager`, you would see this message:

```txt
[https://tlsexpired.no] Error: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
```

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-checkservertrusted.yml }}

{{ run.sh }}

### Observation

The rule identified one instance in the code where `checkServerTrusted(...)` is used without exception handling.

{{ output.txt }}

### Evaluation

The test fails because of the presence of the `checkServerTrusted(...)` method on in the `TrustManager` implementation, as well as the absence of exceptions being thrown.
