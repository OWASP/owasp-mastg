---
title: Use of object persistence using JSON library
platform: android
id: MASTG-TEST-0217
type: [static]
weakness: MASWE-0050
---

## Overview

In Android, object persistence means saving the state or data of an object, allowing you to retrieve and use it later, even after closing the app or restarting the device. By default, JSON data in SharedPreferences or file storage is saved as plaintext. This means that sensitive information such as passwords or personal details could be vulnerable on rooted devices. Additionally, certain JSON libraries, particularly older versions, may have vulnerabilities during deserialization, which could result in code execution or crashes if they encounter unexpected data types.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `JSON` library.

## Observation

The output file shows usages of the object persistance `JSON` library in the code.

## Evaluation

The test fails if `org.json.JSONObject` and `org.json.JSONArray` was found in the code.
