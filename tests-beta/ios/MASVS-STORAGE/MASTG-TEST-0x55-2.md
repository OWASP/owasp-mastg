---
platform: ios
title: Sensitive Data Present In Keyboard Cache
id: MASTG-TEST-0x55-2
type: [dynamic]
---

## Overview

This test checks whether the keyboard cache contains sensitive data from our app.

## Steps

1. Jailbreak a device
2. Reset your iOS device keyboard cache by navigating to `Settings > General > Reset > Reset Keyboard Dictionary`.
3. Exercise the application and identify the functionalities that allow users to enter sensitive data.
4. Use MASTG-TECH-0052 to retrieve the keyboard cache file with the extension `.dat` at `/private/var/mobile/Library/Keyboard/` and its subdirectories.

## Observation

The output should contain all cached strings such as username, passwords, email addresses, and credit card numbers.

## Evaluation

The test case fails if you can find any sensitive cached strings in the list.
