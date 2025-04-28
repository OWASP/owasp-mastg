---
platform: android
title: Uses of Object Persistence with semgrep
id: MASTG-DEMO-0041
code: [kotlin]
test: MASTG-TEST-0266
---

### Sample

The code snippet shows that object persistence being used for storing sensitive information on the device using `org.json.JSONObject` and `org.json.JSONArray`.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-object-persistence.yml }}

{{ run.sh }}

### Observation

The output file shows usages of the object persistence in the code.

{{ output.txt }}

### Evaluation

The test fails if `org.json.JSONObject` and `org.json.JSONArray` was found in the code.
