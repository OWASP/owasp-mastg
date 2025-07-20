---
masvs_category: MASVS-STORAGE
platform: android
id: MASTG-KNOW-0013
title: BouncyCastle KeyStore
deprecated_since: 31
status: deprecated
deprecation_note: BouncyCastle KeyStore was [removed in Android 12 (API level 31) and later](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle).
---

Older Android versions don't include KeyStore, but they _do_ include the KeyStore interface from JCA (Java Cryptography Architecture). You can use KeyStores that implement this interface to ensure the secrecy and integrity of keys stored with KeyStore; BouncyCastle KeyStore (BKS) is recommended. All implementations are based on the fact that files are stored on the filesystem; all files are password-protected.

To create one, use the `KeyStore.getInstance("BKS", "BC") method`, where "BKS" is the KeyStore name (BouncyCastle Keystore) and "BC" is the provider (BouncyCastle). You can also use SpongyCastle as a wrapper and initialize the KeyStore as follows: `KeyStore.getInstance("BKS", "SC")`.

Be aware that not all KeyStores properly protect the keys stored in the KeyStore files.
