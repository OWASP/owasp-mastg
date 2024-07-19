---
title: Insecure Certificate Validation
id: MASWE-0052
alias: insecure-cert-val
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-NETWORK-3]
  masvs-v2: [MASVS-NETWORK-1]
  cwe: [CWE-295]

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
status: draft

---

