---
masvs_v1_id:
- MSTG-RESILIENCE-9
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: ios
title: Testing Obfuscation
masvs_v1_levels:
- R
profiles: [R]
---

## Overview

Attempt to disassemble the Mach-O in the IPA and any included library files in the "Frameworks" directory (.dylib or .framework files), and perform static analysis. At the very least, the app's core functionality (i.e., the functionality meant to be obfuscated) shouldn't be easily discerned. Verify that:

- meaningful identifiers, such as class names, method names, and variable names, have been discarded.
- string resources and strings in binaries are encrypted.
- code and data related to the protected functionality is encrypted, packed, or otherwise concealed.

For a more detailed assessment, you need a detailed understanding of the relevant threats and the obfuscation methods used.
