---
platform: android
title: Sensitive Data in Network Traffic Capture
type: [dynamic, network]
---

## Prerequisites

- [Identify your sensitive data](MASTG-KNOW-0001)
- [Privacy policy](MASTG-TECH-0001)
- [App Store Privacy declarations](MASTG-TECH-0001)

## Steps

1. Start the device.

2. Start [logging sensitive data from network traffic](../../../../../techniques/android/MASTG-TECH-0100.md).

3. Launch and use the app going through the various workflows while inputting sensitive data wherever you can. Especially, places where you know that will trigger network traffic.

## Observation

The **network traffic sensitive data log** including decrypted HTTPS traffic contains the sensitive data you entered in the app.

## Evaluation

The test case fails if you can find the sensitive data you entered in the app within the **network traffic sensitive data log** that is not stated in the App Store Privacy declarations.
