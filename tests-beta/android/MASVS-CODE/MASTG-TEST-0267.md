---
title: Unsafe Deserialization of Untrusted Input Using Parcelable
platform: android
id: MASTG-TEST-0267
type: [static]
weakness: MASWE-0088
profiles: [L1, L2]
---

## Overview

Android's Parcel class, used with the Parcelable interface, allows fast serialization of objects for inter-process communication (IPC). However, deserializing data from untrusted sources without proper validation can lead to serious security risks. An attacker could craft a malicious Parcel to manipulate object fields, bypass logic, or crash the application. This makes the app vulnerable to privilege escalation or denial of service.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `import android.os.Parcelable` and `implements Parcelable`.

## Observation

The output file shows usages of the object Deserialization using `import android.os.Parcelable` and `implements Parcelable` in the code.

## Evaluation

The test fails if the `import android.os.Parcelable` and `implements Parcelable` was found in the code.
