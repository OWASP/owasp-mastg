---
platform: android
title: Detecting Sensitive Data in Network Traffic
tools: [mitmproxy]
code: [kotlin]
---

### Sample

The snippet below shows sample code that sends sensitive data over the network using the `HttpURLConnection` class. The data is sent to `https://httpbin.org/post` which is a dummy endpoint that returns the data it receives.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Start the device, in this case, the Android emulator:

```bash
emulator -avd Pixel_3a_API_33_arm64-v8a -writable-system
```

Run mitmproxy with the custom script for logging sensitive data and dump the relevant traffic to a file.

Note that the script is preconfigured with data that's already considered sensitive for this application. When running this test in a real-world scenario, you should determine what is considered [sensitive data](../../../../../../Document/0x04b-Mobile-App-Security-Testing.md#identifying-sensitive-data "Sensitive Data") based on the app's privacy policy and relevant privacy regulations. One recommended way to do this is by checking the app's privacy policy and the App Store Privacy declarations.

{{ mitm_sensitive_logger.py }}

{{ run.sh }}

Launch the app from Android Studio and click the button which will send the sensitive data over the network. The script will capture the network traffic and log the sensitive data.

### Observation

The script has identified several instances of sensitive data in the network traffic.

- The first instance is a POST request to `https://httpbin.org/post` which contains the sensitive data values in the request body.
- The second instance is a response from `https://httpbin.org/post` which contains the sensitive data values in the response body.

{{ sensitive_data.log }}

### Evaluation

After reviewing the captured network traffic, we can conclude that the test fails because the sensitive data is sent over the network.

This is a dummy example, but in a real-world scenario, you should determine which of the reported instances are privacy-relevant and need to be addressed.

Note that both the request and the response are encrypted using TLS, so they can be considered secure. However, this might represent a privacy issue depending on the relevant privacy regulations and the app's privacy policy. You should now check the privacy policy and the App Store Privacy declarations to see if the app is allowed to send this data to a third-party.
