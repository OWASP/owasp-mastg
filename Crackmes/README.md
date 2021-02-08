# UnCrackable Mobile Apps

<img align="left" width="100px" src="../Document/Images/Other/uncrackable-logo.png" />

Welcome to the UnCrackable Apps for Android and iOS, a collection of mobile reverse engineering challenges. These challenges are used as examples throughout the Mobile Security Testing Guide. Of course, you can also solve them for fun.

## Android

### [UnCrackable App for Android Level 1](Android/Level_01 "Android level 1")

This app holds a secret inside. Can you find it?

- Objective: A secret string is hidden somewhere in this app. Find a way to extract it.
- Author: [Bernhard Mueller](https://github.com/b-mueller "Bernhard Mueller").
- Maintained by the OWASP MSTG leaders.

#### Installation

This app is compatible with Android 4.4 and up.

```shell
  $ adb install UnCrackable-Level1.apk
```

#### Solutions

- [Solution using Frida by c0dmtr1x](https://www.codemetrix.net/hacking-android-apps-with-frida-2/ "Solution by c0dmtr1x")
- [Solution using static analysis](../Document/0x05c-Reverse-Engineering-and-Tampering.md#reviewing-decompiled-java-code "Solution using static analysis")
- [Solution using jdb](../Document/0x05c-Reverse-Engineering-and-Tampering.md#debugging-with-jdb "Solution using jdb")
- [Solution using Frida by Eduardo Novella](https://enovella.github.io/android/reverse/2017/05/18/android-owasp-crackmes-level-1.html "Solution by Eduardo Novella")
- [Solution using Xposed by sh3llc0d3r](http://sh3llc0d3r.com/owasp-uncrackable-android-level1/ "Solution by sh3llc0d3r")
- [Solution using RMS by @mobilesecurity_ (video)](https://youtu.be/P6rNPkM2DdY "Solution by @mobilesecurity_")

### [UnCrackable App for Android Level 2](Android/Level_02 "Android level 2")

This app holds a secret inside. May include traces of native code.

- Objective: A secret string is hidden somewhere in this app. Find a way to extract it.
- Author: [Bernhard Mueller](https://github.com/b-mueller "Bernhard Mueller").
- Special thanks to Michael Helwig for finding and fixing an oversight in the anti-tampering mechanism.
- Maintained by the OWASP MSTG leaders.

#### Installation

This app is compatible with Android 4.4 and up.

```shell
  $ adb install UnCrackable-Level2.apk
```

#### Solutions

- [Solution using Frida and radare2 by c0dmtr1x](https://www.codemetrix.net/hacking-android-apps-with-frida-3/ "Solution by c0dmtr1x").
- [Solution using Frida by Eduardo Novella](https://enovella.github.io/android/reverse/2017/05/20/android-owasp-crackmes-level-2.html "Solution by Eduardo Novella").
- [Solution using patches by sh3llc0d3r](http://sh3llc0d3r.com/owasp-uncrackable-android-level2/ "Solution by sh3llc0d3r").
- [Solution using RMS by @mobilesecurity_ (video)](https://youtu.be/xRQVljerl0A "Solution by @mobilesecurity_").

### [UnCrackable App for Android Level 3](Android/Level_03 "Android level 3")

The crackme from hell!

- Objective: A secret string is hidden somewhere in this app. Find a way to extract it.
- Author: [Bernhard Mueller](https://github.com/b-mueller "Bernhard Mueller").
- Special thanks to Eduardo Novella for testing, feedback and pointing out flaws in the initial build(s).
- Maintained by the OWASP MSTG leaders.

#### Installation

This app is compatible with Android 4.4 and up.

```shell
$ adb install UnCrackable-Level3.apk
```

#### Solutions

- [Solution using Frida by Eduardo Novella](https://enovella.github.io/android/reverse/2017/05/20/android-owasp-crackmes-level-3.html "Solution by Eduardo Novella").
- [Solution using patches by sh3llc0d3r](http://sh3llc0d3r.com/owasp-uncrackable-android-level3/ "Solution by sh3llc0d3r").

### [UnCrackable App for Android Level 4: Radare2 Pay v0.9](Android/Level_04 "Android level 4")

The Radare2 community always dreamed with its decentralized and free currency to allow r2 fans to make payments in places and transfer money between r2 users. A debug version has been developed and it will be supported very soon in many stores and websites. Can you verify that this is cryptographically unbreakable?

Hint: Run the APK in a non-tampered device to play a bit with the app.

- Objectives:
  - 1: There is a master PIN code that generates green tokens (aka r2coins) on the screen. If you see a red r2coin, then this token won't be validated by the community. You need to find out the 4 digits PIN code and the salt employed as well. Flag: `r2con{PIN_NUMERIC:SALT_LOWERCASE}`
  - 2: There is a "r2pay master key" buried in layers of obfuscation and protections. Can you break the whitebox? Flag: `r2con{ascii(key)}`
- Author: [Eduardo Novella](https://github.com/enovella "Eduardo Novella") & [Gautam Arvind](https://github.com/darvincisec "Gautam Arvind").
- Special thanks to [NowSecure](https://www.nowsecure.com "NowSecure") for supporting this crackme.
- Maintained by [Eduardo Novella](https://github.com/enovella "Eduardo Novella") & [Gautam Arvind](https://github.com/darvincisec "Gautam Arvind").

#### Installation

This app is compatible with Android 4.4 and up.

```shell
$ adb install r2pay-v0.9.apk
```

#### Versions
- `v0.9` - Release for `OWASP MSTG`.
  - Source code is available and the compilation has been softened in many ways to make the challenge easier and more enjoyable for newcomers.
- `v1.0` - Release for `R2con CTF 2020`.
  - No source code is available and many extra protections are in place.

#### Solutions R2pay v0.9
- Not yet

#### Solutions R2pay v1.0

- [Solution bypassing protections using Frida/QBDI by Romain Thomas](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part1/ "Solution by Romain Thomas").
- [Solution whitebox key recovery using SCAMarvels by Romain Thomas](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part2/ "Solution by Romain Thomas").

### [Android License Validator](Android/License_01 "Android License Validator")

A brand new Android app sparks your interest. Of course, you are planning to purchase a license for the app eventually, but you'd still appreciate a test run before shelling out $1. Unfortunately no keygen is available!

- Objective: Generate a valid serial key that is accepted by this app.
- Author: [Bernhard Mueller](https://github.com/b-mueller "Bernhard Mueller").
- Maintained by the OWASP MSTG leaders.

#### Installation

Copy the binary to your Android device and run using the shell.

```shell
  $ adb push validate /data/local/tmp
  [100%] /data/local/tmp/validate
  $ adb shell chmod 755 /data/local/tmp/validate
  $ adb shell /data/local/tmp/validate
  Usage: ./validate <serial>
  $ adb shell /data/local/tmp/validate 1234
  Incorrect serial (wrong format).
```

#### Solutions

- [Solution using symbolic execution by Bernhard Mueller](../Document/0x05c-Reverse-Engineering-and-Tampering.md#symbolic-execution "Tampering and Reverse Engineering on Android - Symbolic Execution").

## iOS

### [UnCrackable App for iOS Level 1](iOS/Level_01 "iOS level 1")

This app holds a secret inside. Can you find it?

- Objective: A secret string is hidden somewhere in this binary. Find a way to extract it. The app will give you a hint when started.
- Author: [Bernhard Mueller](https://github.com/b-mueller "Bernhard Mueller")
- Maintained by the OWASP MSTG leaders.

#### Installation

Open the "Device" window in Xcode and drag the IPA file into the list below "Installed Apps".

Note: The IPA is signed with an Enterprise distribution certificate. You'll need to install the provisioning profile and trust the developer to run the app the "normal" way. Alternatively, re-sign the app with your own certificate, or run it on a jailbroken device (you'll want to do one of those anyway to crack it).

#### Solutions

- [Multiple solutions by David Weinstein](https://www.nowsecure.com/blog/2017/04/27/owasp-ios-crackme-tutorial-frida/ "Solutions by David Weinstein").
- [Solution by Ryan Teoh](http://www.ryantzj.com/cracking-owasp-mstg-ios-crackme-the-uncrackable.html "Solution by Ryan Teoh").
- [Solution with Angr by Vikas Gupta](https://serializethoughts.com/2019/10/28/solving-mstg-crackme-angr "Solving iOS UnCrackable 1 Crackme Without Using an iOS Device").
- [Solution by Pietro Oliva](https://0xsysenter.github.io/ios/reversing/arm64/mobile/ipa/frida/instrumentation/crackme/2021/01/09/ios-apps-reverse-engineering-solving-crackmes-part-1.html "Solution by Pietro Oliva").

### [UnCrackable App for iOS Level 2](iOS/Level_02 "iOS level 2")

This app holds a secret inside - and this time it won't be tampered with!

- Objective: Find the secret code - it is related to alcoholic beverages.
- Author: [Bernhard Mueller](https://github.com/b-mueller "Bernhard Mueller").
- Maintained by the OWASP MSTG leaders.

Note: Due to its anti-tampering the app won't run correctly if the main executable is modified and/or re-signed. You'll need to trust the developer run it the standard way on a non-jailbroken device (General Settings -> Profile & Device Management) and to verify the solution.

#### Installation

Open the "Device" window in Xcode and drag the IPA file into the list below "Installed Apps".

Note: The IPA is signed with an Enterprise distribution certificate. You'll need to install the provisioning profile and trust the developer to run the app the "normal" way. Alternatively, re-sign the app with your own certificate, or run it on a jailbroken device (you'll want to do one of those anyway to crack it).

#### Solutions

- [Solution by Ryan Teoh](http://www.ryantzj.com/cracking-owasp-mstg-ios-crackme-the-uncrackable.html "Solution by Ryan Teoh").
- [Solution by Pietro Oliva](https://0xsysenter.github.io/ios/reversing/arm64/mobile/ipa/frida/instrumentation/crackme/2021/02/08/ios-apps-reverse-engineering-solving-crackmes-part-2.html "Solution by Pietro Oliva").

## MSTG Hacking Playground

Did you enjoy working with the Crackmes? There is more! Go to [the MSTG Hacking Playground](https://github.com/OWASP/MSTG-Hacking-Playground "MSTG-playground") and find out!

## Issues with the Crackmes

If the app does not boot, or if there is another bug: file an issue at this repository or at [the one you should not go to (SPOILER ALERT!)](https://github.com/OWASP/mstg-crackmes "OWASP MSTG Crackmes").
