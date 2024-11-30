---
title: Insecure Certificate Validation
id: MASWE-0052
alias: insecure-cert-val
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-NETWORK-3]
  masvs-v2: [MASVS-NETWORK-1]
  cwe: [295]
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager
  - https://developer.android.com/privacy-and-security/risks/unsafe-hostname
refs:
  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf#page=17
  - https://developer.android.com/privacy-and-security/security-ssl#tls-1.3-enabled-by-default
  - https://support.google.com/faqs/answer/7071387?hl=en
  - https://developer.android.com/reference/android/webkit/WebViewClient.html?sjid=15211564825735678155-EU#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)
  - https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket
  - https://wiki.sei.cmu.edu/confluence/display/java/MSC00-J.+Use+SSLSocket+rather+than+Socket+for+secure+data+exchange
draft:
  description: e.g. not checking the certificate chain, not checking the hostname,
    not checking the validity period, not checking the revocation status, etc. The
    certificate validation should be secure by default. This includes the platform-provided
    mechanisms such as NSC/ATS as well as third-party libraries and frameworks.
  topics:
  - via NSC/ATS
  - via manual server trust evaluation (e.g. iOS SecTrust / Android TrustManager.
    okhttpTrustManager).
  - Using a TrustManager that does no certificate validation (e.g. X509TrustManager
    with getAcceptedIssuers returning always null, checkServerTrusted not performing
    any validation, etc.).
  - doesn't accept self-signed/untrusted CAs
  - Custom Trust Anchors, app trusting any user supplied CAs
  - check OS version's default trust anchors on Android
  - insecure TLS settings
  - third-party libraries e.g. okhttp uses MODERN_TLS or RESTRICTED_TLS configs, no
    fallbacks via COMPATIBLE_TLS, no weak TLS version or ciphersuites
  - using SSLSocket or Cordova apps
  - MITM via an arbitrary certificate signed by a trusted CA works
  - WebView clients (e.g. WebViewClient.onReceivedSslError, not TLS errors ignored,
    mixed content, insecure handlers)
status: new

---

## Overview

Apps that do not properly validate TLS certificates during secure communication are susceptible to Machine-in-the-Middle (MITM) attacks and other security threats. This weakness occurs when an app accepts invalid, expired, self-signed, or untrusted certificates without appropriate verification, compromising the integrity and confidentiality of data in transit.

## Impact

- **Machine-in-the-Middle (MITM) Attacks**: Attackers can intercept and manipulate data exchanged between the client and server.
- **Data Exposure**: Sensitive information can be compromised.
- **Unauthorized Access**: Attackers may gain unauthorized access to user accounts or systems by intercepting authentication tokens or credentials.
- **Impersonation of Services**: Users may be deceived into interacting with malicious servers impersonating legitimate services.
- **Data Integrity Loss**: Altered or corrupted data may be accepted by the application, leading to unreliable or malicious outcomes.

## Modes of Introduction

- **Disabling Certificate Validation**: Developers disable or bypass certificate validation checks to simplify development or troubleshoot connectivity issues.
- **Accepting Self-Signed Certificates**: Applications accept self-signed or untrusted certificates without proper validation against trusted Certificate Authorities (CAs).
- **Ignoring Hostname Verification**: Failing to verify that the certificate's hostname matches the server's hostname allows attackers to present valid certificates for other domains.
- **Using Insecure Custom Trust Managers**: Implementing custom certificate validation logic that is incomplete, incorrect, or insecure.
- **Inadequate Error Handling**: Proceeding with connections even when certificate validation errors occur, without alerting the user or terminating the connection.
- **Trusting All Certificates**: Configuring the application to trust all certificates by default, without any validation.

## Mitigations

- **Enforce Strict Certificate Validation**: Always validate TLS certificates against a trusted set of Certificate Authorities (CAs) provided by the operating system or a trusted third party.
- **Enable Hostname Verification**: Ensure that the application's network layer verifies the server's hostname against the certificate's Subject Alternative Name (SAN) or Common Name (CN).
- **Use Standard Trust Managers**: Utilize well-established libraries and platform-provided APIs for certificate validation instead of custom implementations.
- **Handle Validation Errors Properly**: Terminate the connection and alert the user whenever certificate validation fails due to issues like expiration, revocation, or mismatch.
- **Avoid Accepting Self-Signed Certificates**: Do not accept self-signed or untrusted certificates in production environments unless there is a secure mechanism to trust them explicitly.
- **Stay Updated with Security Protocols**: Use the latest versions of TLS protocols and ensure that weak ciphers and protocols are disabled.
