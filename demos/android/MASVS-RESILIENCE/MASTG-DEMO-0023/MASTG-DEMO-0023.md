---
platform: android
title: Uses of Root Detection Techniques with r2
code: [kotlin]
id: MASTG-DEMO-0023
test: MASTG-TEST-0245
---

### Sample

The following code shows an example of root detection on a device.

{{ RootDetection.kt }}

### Steps

1. Unzip the APK package and locate the main binary file (@MASTG-TECH-0007), which in this case is the classes.dex.
2. Open the application's binary file using @MASTG-TOOL-0028 with the -i option to run this script.

{{ root_detection.r2 }}

{{ run.sh }}

### Observation

The output should include information about detected root indicators, such as the presence of su binaries or modified system properties.

### Evaluation

The demo is considered successful if the rooted device is correctly identified, and the application does not mistakenly flag a non-rooted device as rooted. Furthermore, the bypass techniques should not allow complete circumvention of the root detection.

On the other hand, the demo fails if the rooted device is not detected, a non-rooted device is falsely flagged as rooted, or if any of the bypass techniques successfully bypass the root detection mechanism.
