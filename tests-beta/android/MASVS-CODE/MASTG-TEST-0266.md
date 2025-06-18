---
title: Unwanted Object Deserialization Using Serializable
platform: android
id: MASTG-TEST-0266
type: [static]
weakness: MASWE-0088
profiles: [L1, L2]
---

## Overview

In Android and Java, the Serializable interface enables the conversion of object data into a byte stream for storage or transmission.However, deserializing objects from untrusted sources without proper validation can lead to the creation of unwanted or malicious objects.Attackers may take advantage of this by crafting inputs that alter application behavior, resulting in security vulnerabilities like arbitrary code execution, privilege escalation, or denial of service.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `import java.io.Serializable` and `implements Serializable`.

## Observation

The output file shows usages of the object Deserialization using `import java.io.Serializable` and `implements Serializable` in the code.

## Evaluation

The test fails if the `import java.io.Serializable` and `implements Serializable` was found in the code.
