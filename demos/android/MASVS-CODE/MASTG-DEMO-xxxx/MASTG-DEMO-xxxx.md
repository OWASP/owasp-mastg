---
platform: android
title: Uses of Object Persistance with semgrep
id: MASTG-DEMO-xxxx
code: [kotlin]
---

### Sample

The code snippet below shows sample code that object persistence being used for storing sensitive information on the device using `org.json.JSONObject` and `org.json.JSONArray`.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-object-persistance.yml }}

{{ run.sh }}

### Observation

The output file shows usages of the object persistance in the code.

{{ output.txt }}

### Evaluation

The test fails if `org.json.JSONObject` and `org.json.JSONArray` was found in the code.
