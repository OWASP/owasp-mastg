---
platform: android
title: Object Deserialization Using Serializable with semgrep
id: MASTG-DEMO-0041
code: [kotlin]
test: MASTG-TEST-0266
---

### Sample

The code snippet shows the utilization of object deserialization being using `java.io.Serializable` and `implements Serializable`.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-object-deserialization.yml }}

{{ run.sh }}

### Observation

The output file shows usages of the object persistence in the code.

{{ output.txt }}

### Evaluation

The test fails because `java.io.Serializable` and `implements Serializable` were found in the code.

- Line 15 contains the import of `java.io.Serializable`.
- Line 16 contains the import of `implements Serializable`.
