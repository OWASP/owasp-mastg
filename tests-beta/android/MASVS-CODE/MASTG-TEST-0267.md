---
title: Unsafe Deserialization of Untrusted Input Using Parcelable
platform: android
id: MASTG-TEST-0267
type: [static]
weakness: MASWE-0088
profiles: [L1, L2]
---

## Overview

The Parcel class in Android, which works with the Parcelable interface, enables quick serialization of objects for inter-process communication (IPC). However, if you deserialize data from untrusted sources without adequate validation, it can pose significant security threats. An attacker might create a harmful Parcel to alter object fields, circumvent logic, or crash the application. This vulnerability can lead to privilege escalation or denial of service.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `import android.os.Parcelable` and `implements Parcelable`.

## Observation

The output file shows usages of the object Deserialization using `import android.os.Parcelable` and `implements Parcelable` in the code.

## Evaluation

The test fails if the `import android.os.Parcelable` and `implements Parcelable` was found in the code.
