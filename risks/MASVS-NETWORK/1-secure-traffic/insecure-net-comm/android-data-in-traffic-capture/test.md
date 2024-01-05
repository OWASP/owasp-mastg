---
platform: android
title: Sensitive Data in Network Traffic Capture
type: dynamic, network
---

## Prerequisites

- [Identify your sensitive data](MASTG-KNOW-0001)
- [Privacy policy](MASTG-TECH-0001)
- [App Store Privacy declarations](MASTG-TECH-0001)

## Steps

1. [Intercept the network traffic of the app](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/) ensuring that the traffic is decrypted.

2. Launch and use the app going through the various workflows while inputting sensitive data wherever you can. Especially, places where you know that will trigger network traffic.

> Tip: Use unique identifiers (like "1111111111111") so that you can easily be find them later in the test output.

## Observation

The **network traffic capture** including decrypted HTTPS traffic.

## Evaluation

The test case fails if you can find the sensitive data you entered in the app within the **network traffic capture** that is not stated in the App Store Privacy declarations.

## Example

{{ test.sh }}

{{ output.txt }}
