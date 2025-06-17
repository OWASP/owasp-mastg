---
platform: android
title: Object Deserialization Using Parcelable with semgrep
id: MASTG-DEMO-0054
code: [kotlin]
test: MASTG-TEST-0267
profiles: [L1, L2]
---

### Sample

The code snippet shows the utilization of object deserialization being using `import android.os.Parcelable` and `implements Parcelable`.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-object-deserialization-using-parcelable.yml }}

{{ run.sh }}

### Observation

The output file shows usages of the object deserialization using parcelable in the code.

{{ output.txt }}

### Evaluation

The test fails because `import android.os.Parcelable` and `implements Parcelable` were found in the code.
