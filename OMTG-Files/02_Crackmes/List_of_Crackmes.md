# Android

## [UnCrackable App for Android Level 1](https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/01_Android/Level_01/)

This app holds a secret inside. Can you find it?

- Objective: A secret string is hidden somewhere in this app. Find a way to extract it. 
- Author: [Bernhard Mueller](https://github.com/b-mueller)

### Installation

```
$ adb install UnCrackable-Level1.apk
```

### Solutions

- [Static Analysis in the Android Reverse Engineering Guide](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md#user-content-statically-analyzing-java-code)
- [Frida Solution by c0dmtr1x](https://www.codemetrix.net/hacking-android-apps-with-frida-2/)

## [UnCrackable App for Android Level 2](https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/01_Android/Level_02/)

This app holds a secret inside. May include traces of native code.

- Objective: A secret string is hidden somewhere in this app. Find a way to extract it. 
- Author: [Bernhard Mueller](https://github.com/b-mueller)

### Installation

```
$ adb install UnCrackable-Level2.apk
```

### Solutions

- N/A

## [Android License Validator](https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/01_Android/Level_03/)

A brand new Android app sparks your interest. Of course, you are planning to purchase a license for the app eventually, but you'd still appreciate a test run before shelling out $1. Unfortunately no keygen is available! 

- Objective: Generate a valid serial key that is accepted by this app.
- Author: [Bernhard Mueller](https://github.com/b-mueller)

### Installation

Copy the binary to your Android device and run using the shell.

```
$ adb push validate /data/local/tmp
[100%] /data/local/tmp/validate
$ adb shell chmod 755 /data/local/tmp/validate
$ adb shell /data/local/tmp/validate
Usage: ./validate <serial>
$ adb shell /data/local/tmp/validate 1234
Incorrect serial (wrong format).
```

### Solutions

- [Dynamic Symbolic Execution in the Android Reverse Engineering Guide](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md#user-content-symbolic-execution) (by the author)

# iOS

## [UnCrackable App for iOS Level 1](https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/02_iOS/Level_01/)

This app holds a secret inside. Can you find it?

Objective: A secret string is hidden somewhere in this binary. Find a way to extract it. The app will give you a hint when started.

- Author: [Bernhard Mueller](https://github.com/b-mueller)

### Installation

Open the "Device" window in XCode and drag the IPA file into the list below "Installed Apps". 

Note: The IPA is signed with an Enterprise distribution certificate. You'll need to install the provisioning profile and trust the developer to run the app the "normal" way. Alternatively, re-sign the app with your own certificate, or run it on a jailbroken device (you'll want to do one of those anyway to crack it).

### Solutions

- N/A

## [UnCrackable App for iOS Level 2](https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/02_iOS/Level_02/)

This app holds a secret inside - and this time it won't be tampered with!

- Difficulty: Medium
- Author: [Bernhard Mueller](https://github.com/b-mueller)

Objective: Find the secret code - it is related to alcoholic beverages.

Note: Due to its anti-tampering the app won't run correctly if the main executable is modified and/or re-signed. You'll need to trust the developer run it the standard way on a non-jailbroken device (General Settings -> Profile & Device Management) and to verify the solution. 

### Installation

Open the "Device" window in XCode and drag the IPA file into the list below "Installed Apps". 

Note: The IPA is signed with an Enterprise distribution certificate. You'll need to install the provisioning profile and trust the developer to run the app the "normal" way. Alternatively, re-sign the app with your own certificate, or run it on a jailbroken device (you'll want to do one of those anyway to crack it).

### Solutions

- N/A
