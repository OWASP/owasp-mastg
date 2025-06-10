---
title: Insecure Object Deserialization
id: MASWE-0088
alias: insecure-deserialization
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CODE-4]
  android-risks: 
  - https://developer.android.com/privacy-and-security/risks/unsafe-deserialization
draft:
  description: e.g. XML, JSON, java.io.Serializable, Parcelable on Android or NSCoding
    on iOS.
  topics:
  - XML
  - JSON
  - java.io.Serializable
  - Parcelable
  - NSCoding
status: placeholder
refs:
- https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Ke-Android-Parcels-Introducing-Android-Safer-Parcel.pdf
- https://github.com/michalbednarski/ReparcelBug2
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android
---

