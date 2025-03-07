---
platform: android
title: Application using dangerous permissions
id: MASTG-DEMO-0024
code: [kotlin]
---

### Sample

{{ AndroidManifest.xml # AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample manifest file.

{{ ../../../../rules/mastg-android-dangerous-app-permissions.yaml }}

{{ run.sh }}

### Observation

The rule has identified four instances in the AndroidManifest file where the application requires dangerous permissions.

{{ output.txt }}

### Evaluation

The reported instances include:

- Line 3 uses `WRITE_EXTERNAL_STORAGE` permissions.
- Line 4 uses `READ_CONTACTS` permissions.
- Line 5 uses `READ_EXTERNAL_STORAGE` permissions.
- Line 6 uses `ACCESS_FINE_LOCATION` permissions.
