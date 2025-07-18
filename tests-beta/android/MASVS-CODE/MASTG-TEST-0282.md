---
title: Unwanted Object Deserialization Using Serializable
platform: android
id: MASTG-TEST-0282
type: [static]
weakness: MASWE-0088
profiles: [L1, L2]
---

## Overview

Insecure Deserialization is a vulnerability that occurs when an application deserializes untrusted data without sufficient validation. In Android, data can be passed between components via Intent objects. If an application receives a serialized object within an Intent and deserializes it using an unsafe method like `ObjectInputStream.readObject()`, it becomes vulnerable. A malicious application could send a specially crafted Intent containing a serialized object. When the vulnerable app deserializes this object, it can lead to arbitrary code execution, data tampering, or denial of service. In this testcase, it allows for privilege escalation by overwriting the current user's state.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the codebase for usages of `readObject()`.

## Observation

The output file shows usages of the object Deserialization using `readObject()` in the code.

## Evaluation

The test fails due to the application deserializing data from an untrusted `Intent` extra through the insecure `ObjectInputStream.readObject()` method. A malicious application can create a serialized `AdminUser` object, transmit it via an Intent, and have it deserialized by the processIntent method. This action would overwrite the current user and provide the attacker with administrative privileges within the application.
