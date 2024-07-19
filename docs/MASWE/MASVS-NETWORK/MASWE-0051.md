---
title: Unprotected Open Ports
id: MASWE-0051
alias: open-ports
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-NETWORK-2]
  masvs-v2: [MASVS-NETWORK-1]

draft:
  description: e.g. the app uses a server socket and binds to INADDR_ANY or uses a
    loopback address. This allows other apps to connect to the app's server socket
    and communicate with it.
  topics:
  - no loopback
  - no binding to INADDR_ANY
status: draft

---

