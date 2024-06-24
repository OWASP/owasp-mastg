---
platform: android
title: Sensitive Data in Network Traffic Capture
type: [dynamic, network]
prerequisites:
- identify-sensitive-data
- privacy-policy
- app-store-privacy-declarations
---

## Overview

Attackers may capture network traffic from Android devices using an intercepting proxy, such as [OWASP ZAP](/MASTG/tools/network/MASTG-TOOL-0079), [Burp Suite](/MASTG/tools/network/MASTG-TOOL-0077), or [mitmproxy](/MASTG/tools/network/MASTG-TOOL-0097), to analyze the data being transmitted by the app. This works even if the app uses HTTPS, as the attacker can install a custom root certificate on the Android device to decrypt the traffic. Inspecting traffic that is not encrypted with HTTPS is even easier and can be done without installing a custom root certificate for example by using [Wireshark](/MASTG/tools/network/MASTG-TOOL-0081).

The goal of this test is to verify that sensitive data is not being sent over the network, even if the traffic is encrypted. This test is especially important for apps that handle sensitive data, such as financial or health data, and should be performed in conjunction with a review of the app's privacy policy and the App Store Privacy declarations.

## Steps

1. Start the device.
2. Start [logging sensitive data from network traffic](/MASTG/techniques/android/MASTG-TECH-0100).
3. Launch and use the app going through the various workflows while inputting sensitive data wherever you can. Especially, places where you know that will trigger network traffic.

## Observation

The output should contain a network traffic sensitive data log that includes the decrypted HTTPS traffic.

## Evaluation

The test case fails if you can find the sensitive data you entered in the app that is not stated in the App Store Privacy declarations.

Note that this test does not provide any code locations where the sensitive data is being sent over the network. In order to identify the code locations, you can use static analysis tools like [semgrep](https://semgrep.dev/) or dynamic analysis tools like [Frida](/MASTG/tools/generic/MASTG-TOOL-0031).
