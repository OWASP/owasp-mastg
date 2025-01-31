---
title: App Custom PIN Can Be Extracted or Derived from Local Storage
id: MASWE-0043
alias: custom-pin-extraction
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-2, MASVS-CRYPTO-2]

draft:
  description: It's better to use the OS Local Auth / bind to a key stored in the
    platform KeyStore.
  topics:
  - use the OS Local Auth
  - binding to keys stored in the platform KeyStore
status: draft

---

## Overview

Applications often allow a user to authenticate using an app-specific PIN. The PIN itself serves as a credential to authenticate to the application and should be treated as sensitive information. Due to the nature of the PIN, it is not possible to protect it with the system's keystore as that would require a double authentication (first the device's PIN, then the app's PIN).

Local storage of the PIN code has inherent dangers, as the PIN may be extracted through physical access or on a compromised (rooted/jailbroken) device.

In a correct setup, it should not be possible to extract the app's PIN from the local storage, nor derive it locally. Additionally, since a PIN has low entropy, it should not be possible to bruteforce the correct value.

## Impact

- **Extraction of PIN from app**: If the PIN is stored locally, an attacker can extract it using various techniques (backups, exploits, ...) and use the PIN to authenticate either on the victim's device, or on an attacker controlled device.
- **Bruteforce of PIN locally**: If the PIN can be bruteforced locally based on information available in the local storage of the application, an attacker can dervice the PIN and authenticate either ont he victim's device, or on an attacker controlled device.
- **Bruteforce of PIN on backend**: If the PIN is used directly on the backend to authenticate the user, an attacker can bruteforce the PIN directly on the backend to obtain a valid session.

## Modes of Introduction

- **Implementation of custom cryptographic algorithm**: The PIN code needs to be converted into an active session during authentication. By implementing a vulnerable cryptographic algorithm, the PIN may be extracted or bruteforced.

## Mitigation

Secure authentication via a custom app PIN is only possible if:

- There is an initial secure onboarding flow (e.g. normal credentials, oauth, ...)
- The application has a backend available which can provide either an active session or the keys required to decrypt locally stored data.

The general solution to this problem is to store cryptographic secrets during the initial secure onboarding step and combine them with the user-provided PIN to authenticate to the backend. The backend can then either return a session token so that the application can obtain authenticated data, or a cryptographic key which can be used to decrypt locally stored data.

Potential industry standards to use:

- [OCRA: OATH Challenge-Response Algorithm](https://www.rfc-editor.org/rfc/rfc6287). Note that the output length can be chosen much higher than the proposed configurations to protect against brute-force attacks.
- [The OPAQUE Asymmetric PAKE Protocol](https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-02.html)
