---
masvs_v1_id:
- MSTG-PLATFORM-8
masvs_v2_id:
- MASVS-CODE-4
platform: ios
title: Testing Object Persistence
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

All different flavors of object persistence share the following concerns:

- If you use object persistence to store sensitive information on the device, then make sure that the data is encrypted: either at the database level, or specifically at the value level.
- Need to guarantee the integrity of the information? Use an HMAC mechanism or sign the information stored. Always verify the HMAC/signature before processing the actual information stored in the objects.
- Make sure that keys used in the two notions above are safely stored in the KeyChain and well protected. See the chapter "[Data Storage on iOS](../../../Document/0x06d-Testing-Data-Storage.md)" for more details.
- Ensure that the data within the deserialized object is carefully validated before it is actively used (e.g., no exploit of business/application logic is possible).
- Do not use persistence mechanisms that use [Runtime Reference](https://developer.apple.com/documentation/objectivec/objective-c_runtime "Objective-C Runtime Reference") to serialize/deserialize objects in high-risk applications, as the attacker might be able to manipulate the steps to execute business logic via this mechanism (see the chapter "[iOS Anti-Reversing Defenses](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md)" for more details).
- Note that in Swift 2 and beyond, a [Mirror](https://developer.apple.com/documentation/swift/mirror "Mirror") can be used to read parts of an object, but cannot be used to write against the object.

## Dynamic Analysis

There are several ways to perform dynamic analysis:

- For the actual persistence: Use the techniques described in the "Data Storage on iOS" chapter.
- For the serialization itself: Use a debug build or use Frida / objection to see how the serialization methods are handled (e.g., whether the application crashes or extra information can be extracted by enriching the objects).
