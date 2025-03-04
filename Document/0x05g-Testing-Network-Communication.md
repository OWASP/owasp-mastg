---
masvs_category: MASVS-NETWORK
platform: android
---

# Android Network Communication

## Overview

Almost every Android app acts as a client to one or more remote services. As this network communication usually takes place over untrusted networks such as public Wi-Fi, classical network based-attacks become a potential issue.

Most modern mobile apps use variants of HTTP-based web services, as these protocols are well-documented and supported.

### Android Network Security Configuration

Starting on Android 7.0 (API level 24), Android apps can customize their network security settings using the so-called [Network Security Configuration](https://developer.android.com/training/articles/security-config) feature which offers the following key capabilities:

- **Cleartext traffic**: Protect apps from accidental usage of cleartext traffic (or enables it).
- **Custom trust anchors**: Customize which Certificate Authorities (CAs) are trusted for an app's secure connections. For example, trusting particular self-signed certificates or restricting the set of public CAs that the app trusts.
- **Certificate pinning**: Restrict an app's secure connection to particular certificates.
- **Debug-only overrides**: Safely debug secure connections in an app without added risk to the installed base.

If an app defines a custom Network Security Configuration, you can obtain its location by searching for `android:networkSecurityConfig` in the AndroidManifest.xml file.

```xml
<application android:networkSecurityConfig="@xml/network_security_config"
```

In this case the file is located at `@xml` (equivalent to /res/xml) and has the name "network_security_config" (which might vary). You should be able to find it as "res/xml/network_security_config.xml". If a configuration exists, the following event should be visible in the system logs (@MASTG-TECH-0009):

```bash
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

The Network Security Configuration is [XML-based](https://developer.android.com/training/articles/security-config#FileFormat) and can be used to configure app-wide and domain-specific settings:

- `base-config` applies to all connections that the app attempts to make.
- `domain-config` overrides `base-config` for specific domains (it can contain multiple `domain` entries).

For example, the following configuration uses the `base-config` to prevent cleartext traffic for all domains. But it overrides that rule using a `domain-config`, explicitly allowing cleartext traffic for `localhost`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
    </domain-config>
</network-security-config>
```

Learn more:

- ["A Security Analyst’s Guide to Network Security Configuration in Android P"](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [Android Developers - Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Codelab - Network Security Configuration](https://developer.android.com/codelabs/android-network-security-config)

#### Default Configurations

The default configuration for apps targeting Android 9 (API level 28) and higher is as follows:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

The default configuration for apps targeting Android 7.0 (API level 24) to Android 8.1 (API level 27) is as follows:

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

The default configuration for apps targeting Android 6.0 (API level 23) and lower is as follows:

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

### Certificate Pinning

[Certificate pinning](0x04f-Testing-Network-Communication.md/#restricting-trust-identity-pinning) can be employed in Android apps to safeguard against Machine-in-the-Middle (MITM) attacks by ensuring that the app communicates exclusively with remote endpoints possessing specific identities.

While effective when implemented correctly, insecure implementations potentially enable attackers to read and modify all communication. For more general details on pinning, refer to @MASWE-0047.

Several approaches to certificate pinning exist, depending on the app's API level and the libraries used. Below, we highlight the most common methods. For a deeper dive into the specific implementations, see ["Deep Dive into Certificate Pinning on Android"](https://securevale.blog/articles/deep-dive-into-certificate-pinning-on-android/).

**Important Considerations:**

Certificate pinning is a **hardening practice**, but it is not foolproof. There are multiple ways an attacker can bypass it, such as:  

- **Modifying the certificate validation logic** in the app's `TrustManager`.  
- **Replacing pinned certificates** stored in resource directories (`res/raw/`, `assets/`).  
- **Altering or removing pins** in the Network Security Configuration.  

Any such modification **invalidates the APK signature**, requiring the attacker to **repackage and re-sign the APK**. To mitigate these risks, additional protections such as integrity checks, runtime verification, and obfuscation may be required. For more information on the specific techniques, see @MASTG-TECH-0012.

#### Pinning via Network Security Configuration (API 24+)

The **Network Security Configuration (NSC)** is the preferred and recommended way to implement certificate pinning in Android, as it provides a declarative, maintainable, and secure approach without requiring code changes. It applies to all network traffic managed by the Android framework within the app, including `HttpsURLConnection`-based connections and `WebView` requests (unless a custom `TrustManager` is used). For communication from native code, NSC does not apply, and other mechanisms need to be considered.

When attempting to establish a connection to a remote endpoint, the system will:

- Get and validate the incoming certificate.
- Extract the public key.
- Calculate a digest over the extracted public key.
- Compare the digest with the set of local pins.

If at least one of the pinned digests matches, the certificate chain will be considered valid and the connection will proceed.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <!-- Use certificate pinning for OWASP website access including sub domains -->
        <domain includeSubdomains="true">owasp.org</domain>
        <pin-set expiration="2028-12-31">
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Intermediate CA of the OWASP website server certificate -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Root CA of the OWASP website server certificate -->
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Important Considerations:**

- **Backup Pins:** Always include a backup pin to maintain connectivity if the primary certificate changes unexpectedly.
- **Expiration Dates:** Set an appropriate [expiration date](https://developer.android.com/privacy-and-security/security-config#CertificatePinning) and ensure timely updates to prevent the app from bypassing pinning after the date has passed.
- **Scope of Application:** Be aware that this configuration applies only to connections made using `HttpsURLConnection` or libraries that rely on it. Other networking libraries or frameworks may require separate pinning implementations.

#### Pinning using Custom TrustManagers

Before Network Security Configuration became available, the recommended way to implement certificate pinning was to create a custom `TrustManager` (using `javax.net.ssl` APIs) and override the default certificate validation. You can still use this approach on modern Android versions for flexibility or when you need more direct control.

This approach involves:

1. Loading the server's certificate(s) into a `KeyStore`.
2. Creating a custom `TrustManager` that only trusts the certificate(s) in the `KeyStore`.
3. Initializing an `SSLContext` with the custom `TrustManager`.
4. Applying the custom `SSLContext` as the socket factory for the network connections (e.g., `HttpsURLConnection`).

**Important Note:** This is a **low-level approach and is prone to errors** if not done carefully. Some key considerations include:

- [`SSLSocket` does not automatically verify hostnames](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket), so you must handle this manually using a `HostnameVerifier` with a safe implementation (this includes explicitly checking the return value of `HostnameVerifier.verify()`). More information can be found in the [Android documentation](https://developer.android.com/privacy-and-security/risks/unsafe-hostname).
- [Do **not** include a "trust-all" `TrustManager`](https://developer.android.com/privacy-and-security/security-ssl#UnknownCa) that silently accepts all certificates. This opens the door for attackers to intercept and modify user data with minimal effort.

#### Pinning using Third-party Libraries

Several third-party libraries offer built-in support for certificate pinning, simplifying the implementation process in some cases. These libraries typically utilize the custom `TrustManager` method, providing higher-level abstractions and additional features. Notable examples include:

For example, [OkHttp](https://github.com/square/okhttp)'s offers pinning in its `CertificatePinner`. Under the hood, it uses a custom `TrustManager` to enforce pinning rules.

#### Pinning in WebViews

For in-app `WebView` traffic on Android, the easiest approach is to rely on the **Network Security Configuration**. Since Android automatically applies NSC rules to WebView traffic within the same application, any pinning rules you set up in `network_security_config.xml` will also apply to resources loaded in that WebView.

If you need additional customization beyond what NSC offers, you could implement pinning by intercepting requests at the WebView level (e.g., using `shouldInterceptRequest` and [a custom `TrustManager`](#pinning-using-custom-trustmanagers)), but in most cases the built-in support is sufficient and simpler.

#### Pinning in Native Code

It's also possible to implement pinning in [native code](https://developer.android.com/ndk) (C/C++/Rust). By embedding or dynamically verifying certificates within compiled native libraries (`.so` files), you can increase the difficulty of bypassing or modifying the pinning checks via typical APK reverse engineering.

That said, this approach requires significant security expertise and a careful design to manage certificates or public key hashes in native space. Maintenance and debugging also typically become more complex.

#### Pinning in Cross-Platform Frameworks

Cross-platform frameworks like Flutter, React Native, Cordova, and Xamarin often require special considerations for certificate pinning, as they may not use the same network stack as native apps. For example, Flutter relies on its own Dart `HttpClient` (with BoringSSL) instead of the platform's networking stack, while Cordova makes network requests through JavaScript in a WebView. As a result, pinning behavior varies—some frameworks provide built-in configuration options, others rely on third-party plugins, and some offer no direct support but allow manual implementation via APIs. Understanding how a framework handles networking is crucial for ensuring proper pinning enforcement.

### Security Provider

Android relies on a [security provider](https://developer.android.com/training/articles/security-gms-provider.html "Update your security provider to protect against SSL exploits") to provide SSL/TLS-based connections. The problem with this kind of security provider (one example is [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")), which comes with the device, is that it often has bugs and/or vulnerabilities.

To avoid known vulnerabilities, developers need to make sure that the application will install a proper security provider.
Since July 11, 2016, Google [has been rejecting Play Store application submissions](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (both new applications and updates) that use vulnerable versions of OpenSSL.
