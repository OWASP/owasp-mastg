---
title: Check the App Package for Sensitive Data
profiles:

static_keywords:
  - 

apis:
  -

locations:
  - res/values/strings.xml
  - local.properties
  - gradle.properties

---

## Overview

This test case focuses on identifying potentially sensitive data stored by an application in its package. The app package is considered public since it can be obtained and accessed very easily.

## Steps

Verify common locations of secrets:

- resources (typically at res/values/strings.xml)
  Example:

  ```xml
  <resources>
      <string name="app_name">SuperApp</string>
      <string name="hello_world">Hello world!</string>
      <string name="action_settings">Settings</string>
      <string name="secret_key">My_Secret_Key</string>
    </resources>
  ```

- build configs, such as in local.properties or gradle.properties
  Example:

  ```default
  buildTypes {
    debug {
      minifyEnabled true
      buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
    }
  }
  ```

## Evaluation

TBD

## Mitigation

TBD
