---
platform: android
title: Application using unsafe permissions.
id: MASTG-DEMO-0023
code: [java]
---

### Sample

{{ AndroidManifest.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample manifest file.

{{ ../../../../rules/mastg-android-unsafe-app-permissions.yaml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the AndroidManifest file where the application requires unsafe permissions.

{{ output.txt }}

### Evaluation

The reported instances include:

- Line 5 uses `INTERNET` permissions.
- Line 6 uses `WRITE_EXTERNAL_STORAGE` permissions.
- Line 7 uses `READ_CONTACTS` permissions.
- Line 8 uses `READ_EXTERNAL_STORAGE` permissions.
- Line 9 uses `ACCESS_FINE_LOCATION` permissions.