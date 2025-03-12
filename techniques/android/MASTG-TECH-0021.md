---
title: Information Gathering - API Usage
platform: android
---

The Android platform provides many in-built libraries for frequently used functionalities in applications, for example cryptography, Bluetooth, NFC, network or location libraries. Determining the presence of these libraries in an application can give us valuable information about its nature.

For instance, if an application is importing `javax.crypto.Cipher`, it indicates that the application will be performing some kind of cryptographic operation. Fortunately, cryptographic calls are very standard in nature, i.e, they need to be called in a particular order to work correctly, this knowledge can be helpful when analyzing cryptography APIs. For example, by looking for the `Cipher.getInstance` function, we can determine the cryptographic algorithm being used. With such an approach we can directly move to analyzing cryptographic assets, which often are very critical in an application. Further information on how to analyze Android's cryptographic APIs is discussed in the section "[Android Cryptographic APIs](../../Document/0x05e-Testing-Cryptography.md "Android Cryptographic APIs")".

Similarly, the above approach can be used to determine where and how an application is using NFC. For instance, an application using Host-based Card Emulation for performing digital payments must use the `android.nfc` package. Therefore, a good starting point for NFC API analysis would be to consult the [Android Developer Documentation](https://developer.android.com/guide/topics/connectivity/nfc/hce "Host-based card emulation overview") to get some ideas and start searching for critical functions such as `processCommandApdu` from the `android.nfc.cardemulation.HostApduService` class.
