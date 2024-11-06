---
title: Compiler Provided Security Features
id: MASWE-0116
alias: compiler-provided-security-features
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CODE-3,MASVS-CODE-4]

draft:
  description: e.g., PIC, stack canaries
  topics:
  - PIC
  - stack canaries
  note: 
    - PIC cannot be switched off in newer versions of Android, the ndk does not link against such libraries anymore [source](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_main.cpp;l=397?q=linker_main&ss=android%2Fplatform%2Fsuperproject%2Fmain). 
status: draft

---

