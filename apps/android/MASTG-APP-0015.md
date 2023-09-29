---
title: Android UnCrackable L4
platform: android
source: https://mas.owasp.org/crackmes/Android#android-uncrackable-l4
---

The Radare2 community always dreamed with its decentralized and free currency to allow r2 fans to make payments in places and transfer money between r2 users. A debug version of the r2Pay app has been developed and it will be supported very soon in many stores and websites. Can you verify that this is cryptographically unbreakable?

Hint: Run the APK in a non-tampered device to play a bit with the app.

1. There is a master PIN code that generates green tokens (aka r2coins) on the screen. If you see a red r2coin, then this token won't be validated by the community. You need to find out the 4 digits PIN code and the salt employed as well. Flag: `r2con{PIN_NUMERIC:SALT_LOWERCASE}`
2. There is a "r2pay master key" buried in layers of obfuscation and protections. Can you break the whitebox? Flag: `r2con{ascii(key)}`

**Versions:**

- `v0.9` - Release for OWASP MAS: Source code is available and the compilation has been softened in many ways to make the challenge easier and more enjoyable for newcomers.
- `v1.0` - Release for R2con CTF 2020: No source code is available and many extra protections are in place.

> Created and maintained by [Eduardo Novella](https://github.com/enovella "Eduardo Novella") & [Gautam Arvind](https://github.com/darvincisec "Gautam Arvind"). Special thanks to [NowSecure](https://www.nowsecure.com "NowSecure") for supporting this crackme.
