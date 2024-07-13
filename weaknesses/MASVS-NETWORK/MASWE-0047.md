---
title: Insecure Identity Pinning
id: MASWE-0047
alias: insecure-pinning
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-NETWORK-4]
  masvs-v2: [MASVS-NETWORK-2]

draft:
  description: e.g. via NSC/ATS, okhttp CertificatePinner, volley, trustkit, Cordova,
    AFNetworking SSLPinningMode
  topics:
  - NSC/ATS
  - net-frameworks e.g. okhttp CertificatePinner, volley, trustkit, Cordova, AFNetworking
    SSLPinningMode
  - Dynamic Pinning e.g. via the ssl-pinning-android library
  - Check for MITM resiliency, e.g. with trusted interceptor cert. consider "proxy
    unaware apps"
status: draft

---

