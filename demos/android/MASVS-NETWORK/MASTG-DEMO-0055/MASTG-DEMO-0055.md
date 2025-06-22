---
platform: android
title: Use of the HostnameVerifier that Allows Any Hostname
id: MASTG-DEMO-0055
code: [kotlin]
test: MSTG-TEST-0283
---

### Sample

This sample connects to a URL with an subject alternative name that does not match the hostname and configures a `HostnameVerifier` that allows any hostname.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-hostname-verification.yml }}

{{ run.sh }}

### Observation

The rule identified one instance of the use of the `HostnameVerifier` in the code.

{{ output.txt }}

### Evaluation

The test fails because the app uses a `HostnameVerifier` that allows any hostname.

In this case, since the rule only checks for the presence of a `HostnameVerifier` and does not validate the implementation of the verifier, you need to manually validate the app's reverse-engineered code and inspect the provided code locations.

The rule points to MastgTest_reversed.java, where we can see the following code:

```java
            connection.setHostnameVerifier(new HostnameVerifier() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda0
                @Override // javax.net.ssl.HostnameVerifier
                public final boolean verify(String str, SSLSession sSLSession) {
                    return MastgTest.fetchUrl$lambda$1(str, sSLSession);
                }
            });
            ...

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean fetchUrl$lambda$1(String hostname, SSLSession sSLSession) {
        Log.w("HOSTNAME_VERIFIER", "Insecurely allowing host: " + hostname);
        return true;
    }
```

We can see how:

- the app sets a custom `HostnameVerifier` on the HTTPS connection.
- the verifier calls `fetchUrl$lambda$1`, which logs a warning and returns `true`.

This way we can conclude that the hostname verification does **not** properly validate that the server's hostname matches the certificate subject alternative name.
