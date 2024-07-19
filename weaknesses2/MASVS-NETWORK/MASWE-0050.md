---
title: Cleartext Traffic
id: MASWE-0050
alias: cleartext-traffic
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-NETWORK-2]
  masvs-v2: [MASVS-NETWORK-1]
  cwe: [CWE-319]

draft:
  description: The app sends or receives data over an insecure channel, such as HTTP,
    FTP, or SMTP. This data can be intercepted and read by an attacker without needing
    to perform Man-in-the-Middle attacks. The app should use HTTPS, SFTP, or SMTPS
    instead.
  topics:
  - exceptions and if justifications are given using the platform provided mechanisms
    (Secure by Default Configuration).
  - Cleartext Traffic allowed in App Network Configuration (usesCleartextTraffic in
    Android Manifest, cleartextTrafficPermitted in NSC, ATS allowInsecureLoads)
  - cleartext in traffic capture
  - Usage of HTTP traffic (e.g. HTTP URLs)
  - cross-platform framework e.g. Flutter, Xamarin
  - use of low-level APIs e.g. SSLSocket on Android or Network on iOS. ATS doesn't
    apply there. Prefer high-level API calls such as Android HttpsURLConnection/iOS
    URLSession.
  - configs./ input params, logic e.g. on third-party or low-level frameworks such
    as SSLSocket on Android or Network on iOS
  - Watch Communications
  - Peer-to-peer communications (e.g. WiFi-direct, Nearby)
status: draft

---

