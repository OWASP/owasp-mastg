---
title: Improper Use of Message Authentication Code (MAC)
id: MASWE-0024
alias: improper-mac
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [327, 807, 915]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- https://csrc.nist.gov/pubs/sp/800/224/ipd
- https://datatracker.ietf.org/doc/html/rfc6151
- https://web.archive.org/web/20170810051504/http://www.tcs.hut.fi/old/papers/aura/aura-csfws97.pdf
- https://en.wikipedia.org/wiki/Replay_attack
draft:
  description: Improper use of MACs in security sensitive contexts affecting data integrity.
  topics:
  - Using HMAC with keys with insufficient entropy
  - Using HMAC with missing timestamp (or nonce)
  - Using MAC‑then‑encrypt or encrypt‑then‑MAC incorrectly, leaking information via timing or error messages
  - Allowing predictors (users or attackers) to control data inputs, creating scenarios where forged or replayed tags bypass integrity checks.
  - Hash functions lacking collision resistance (e.g., MD5 or SHA‑1 used in HMAC)
  - Use of non‑cryptographic checksums (e.g., CRC‑32 instead of HMAC)
  - MAC constructions that fail outside narrow assumptions (e.g., raw CBC‑MAC on variable‑length messages)
  - Tags that are too short significantly lower the effort required for forgery
status: placeholder

---

