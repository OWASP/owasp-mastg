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

Attackers may capture network traffic from Android devices using an intercepting proxy, such as [OWASP ZAP](https://www.zaproxy.org/), [Burp Suite](https://portswigger.net/burp), or [mitmproxy](https://mitmproxy.org/), to analyze the data being transmitted by the app. This works even if the app uses HTTPS, as the attacker can install a custom root certificate on the Android device to decrypt the traffic. Inspecting traffic that is not encrypted with HTTPS is even easier and can be done without installing a custom root certificate for example by using [Wireshark](https://www.wireshark.org/).

## Steps

1. Start the device.

2. Start [logging sensitive data from network traffic](../../../../../techniques/android/MASTG-TECH-0100.md).

3. Launch and use the app going through the various workflows while inputting sensitive data wherever you can. Especially, places where you know that will trigger network traffic.

## Observation

The **network traffic sensitive data log** including decrypted HTTPS traffic contains the sensitive data you entered in the app.

## Evaluation

The test case fails if you can find the sensitive data you entered in the app within the **network traffic sensitive data log** that is not stated in the App Store Privacy declarations.
