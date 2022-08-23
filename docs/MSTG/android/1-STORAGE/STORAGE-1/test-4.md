---
title: Check Shared preferences
profiles:

static_keywords:
  - shared_prefs

apis:
  - SharedPreferences
  - EncryptedSharedPreferences

locations:
  - 

---

## Overview

TBD

## Steps

Check Shared Preferences that are stored as XML files (in `/data/data/<package-name>/shared_prefs`) for sensitive information. Shared Preferences are insecure and unencrypted by default. Some apps might opt to use [secure-preferences](https://github.com/scottyab/secure-preferences "Secure-preferences encrypts the values of Shared Preferences") to encrypt the values stored in Shared Preferences.

## Evaluation

TBD

## Mitigation

TBD
