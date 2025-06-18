---
platform: android
title: Use of a TrustManager that Does Not Validate Certificate Chains
id: MASTG-DEMO-0033
code: [kotlin]
test: MSTG-TEST-0234-1
---

### Sample

This sample demonstrates the insecure use of a custom `TrustManager` that ignores certificate chain validity. It connects to <https://tlsexpired.no>, which has an expired SSL certificate.

{{ MastgTest.kt # MastgTest_reversed.java }}

If the app wouldn't use the insecure `TrustManager`, you'd see this message:

```txt
[https://tlsexpired.no] Error: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
```

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-checkservertrusted.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where `checkServerTrusted` is used without the use of exception handling. The specified line numbers can be located in the original code for further investigation and remediation.

### Evaluation

Review each of the reported instances.

- Line 128-133 and line 214-219 contains the `checkServerTrusted` function which doesn't throw any `CertificateException`, as it only contains a log statement. This is dangerous as it suppresses all server certificate issues.
