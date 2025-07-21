---
masvs_category: MASVS-CRYPTO
platform: android
title: Security Provider
---

Android relies on the `java.security.Provider` class to implement Java Security services. These providers are crucial to ensure secure network communications and secure other functionalities which depend on cryptography.

The list of security providers included in Android varies between versions of Android and the OEM-specific builds. Some security provider implementations in older versions are now known to be less secure or vulnerable. Thus, Android applications should not only choose the correct algorithms and provide a good configuration, in some cases they should also pay attention to the strength of the implementations in the legacy security providers.

You can list the set of existing security providers using following code:

```java
StringBuilder builder = new StringBuilder();
for (Provider provider : Security.getProviders()) {
    builder.append("provider: ")
            .append(provider.getName())
            .append(" ")
            .append(provider.getVersion())
            .append("(")
            .append(provider.getInfo())
            .append(")\n");
}
String providers = builder.toString();
//now display the string on the screen or in the logs for debugging.
```

This is the output for Android 9 (API level 28) running in an emulator with Google Play APIs:

```default
provider: AndroidNSSP 1.0(Android Network Security Policy Provider)
provider: AndroidOpenSSL 1.0(Android's OpenSSL-backed security provider)
provider: CertPathProvider 1.0(Provider of CertPathBuilder and CertPathVerifier)
provider: AndroidKeyStoreBCWorkaround 1.0(Android KeyStore security provider to work around Bouncy Castle)
provider: BC 1.57(BouncyCastle Security Provider v1.57)
provider: HarmonyJSSE 1.0(Harmony JSSE Provider)
provider: AndroidKeyStore 1.0(Android KeyStore security provider)
```

## Updating security provider

Keeping up-to-date and patched component is one of security principles. The same applies to `provider`. Application should check if used security provider is up-to-date and if not, [update it](https://developer.android.com/training/articles/security-gms-provider "Updating security provider").

## Older Android versions

For some applications that support older versions of Android (e.g., only used on versions lower than Android 7.0 (API level 24)), bundling an up-to-date library may be the only option. Conscrypt library is a good choice in this situation to keep the cryptography consistent across the different API levels and avoid having to import [Bouncy Castle](https://www.bouncycastle.org/documentation/documentation-java/ "Bouncy Castle in Java") which is a heavier library.

[Conscrypt for Android](https://github.com/google/conscrypt#android "Conscrypt - A Java Security Provider") can be imported this way:

```groovy
dependencies {
  implementation 'org.conscrypt:conscrypt-android:last_version'
}
```

Next, the provider must be registered by calling:

```kotlin
Security.addProvider(Conscrypt.newProvider())
```
