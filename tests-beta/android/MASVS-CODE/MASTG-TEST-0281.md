---
title: Testing Local Storage for Input Validation with Semgrep
platform: android
id: MASTG-TEST-0281
type: [static]
weakness: MASWE-0088
---

## Overview

Android provides `SharedPreferences` for storing key-value pairs of primitive data and strings. When structured data such as JSON or HTML is stored using `putString()` or `putStringSet()` without proper validation, it can lead to security issues like tampering or injection. This is particularly risky if the stored data is later trusted and used directly by the app.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `putString`, `getString`, `putStringSet`, and `getStringSet` methods from the `SharedPreferences` API.

## Observation

The output file shows usages of object persistence using string-based storage (`putString`, `getString`, etc.) in the code.

## Evaluation

The test fails if `putString()`, `putStringSet()`, `getString()` or `getStringSet()` are found in the code and used to store or retrieve JSON, HTML, or other potentially unsafe input.
