---
masvs_category: MASVS-STORAGE
platform: android
title: BouncyCastle KeyStore
deprecated_since: 28
status: deprecated
deprecation_note: "While the BKS (BouncyCastle Keystore) was not removed from the system [KeyStore](https://developer.android.com/reference/java/security/KeyStore) providers, BouncyCastle support for cryptographic operations on Android was [deprecated in Android 9 (API level 28)](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms) and finally [removed in Android 12 (API level 31)](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle)."
covered_by: [MASTG-KNOW-0043]
---

Older Android versions don't include [KeyStore](https://developer.android.com/reference/java/security/KeyStore), but they _do_ include the KeyStore interface from JCA (Java Cryptography Architecture). You can use KeyStores that implement this interface to ensure the secrecy and integrity of keys stored with KeyStore; BouncyCastle KeyStore (BKS) is recommended. All implementations are based on the fact that files are stored on the filesystem; all files are password-protected.

To create one, use the `KeyStore.getInstance("BKS", "BC") method`, where "BKS" is the KeyStore name (BouncyCastle Keystore) and "BC" is the provider (BouncyCastle). You can also use SpongyCastle as a wrapper and initialize the KeyStore as follows: `KeyStore.getInstance("BKS", "SC")`.

Be aware that not all KeyStores properly protect the keys stored in the KeyStore files.
