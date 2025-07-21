---
masvs_category: MASVS-CRYPTO
platform: ios
title: Random Number Generator
---

Apple provides a [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") API, which generates cryptographically secure random numbers.

The Randomization Services API uses the `SecRandomCopyBytes` function to generate numbers. This is a wrapper function for the `/dev/random` device file, which provides cryptographically secure pseudorandom values from 0 to 255. Make sure that all random numbers are generated with this API. There is no reason for developers to use a different one.
