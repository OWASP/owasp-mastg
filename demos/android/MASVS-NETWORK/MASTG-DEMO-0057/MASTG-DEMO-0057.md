---
platform: android
title: Network Security Configuration Allows User-Added Certificates
id: MASTG-DEMO-0057
code: [xml, kotlin]
test: MSTG-TEST-0286
---

### Sample

This sample Kotlin code fetches the @MASTG-TOOL-0143 server <https://mitm-software.badssl.com/> using `HttpsURLConnection`, which is not normally allowed because the certificate is not trusted by the system. However, due to the Network Security Configuration that permits user-added CA certificates, the connection is allowed to proceed.

{{ MastgTest.kt # AndroidManifest.xml # AndroidManifest_reversed.xml # network_security_config.xml }}

!!! note "Running the app"

    You don't need to run the app on a device or emulator to test this demo because it focuses on the Network Security Configuration. However, if you want to run the app and verify that the connection is allowed, some additional preparation is required:

    1. Obtain the root CA certificate for the server. For this example, obtain it  here: <https://github.com/chromium/badssl.com/blob/master/certs/src/crt/ca-mitm-software.crt>
    2. Copy the certificate file onto the device or emulator. For example, use the command `adb push ca-mitm-software.crt /sdcard/Download/`.
    3. On the device open **Settings > Security > Encryption & credentials > Install from storage** and select your certificate file. Confirm it installs under "User credentials".

### Steps

First of all we obtain the AndroidManifest.xml file (`AndroidManifest_reversed.xml`), which contains the `android:networkSecurityConfig` attribute pointing to the app's Network Security Configuration file (`network_security_config.xml`).

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-insecure-trust-anchors.yml }}

{{ run.sh }}

### Observation

The rule has identified an element in the Network Security Configuration that allows user-added CA certificates.

{{ output.txt }}

### Evaluation

The test fails due to the `<certificates src="user" />` element in the Network Security Configuration which allows user-added CA certificates.
