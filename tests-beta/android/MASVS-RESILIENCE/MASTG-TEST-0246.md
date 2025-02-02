---
title: Root Detection Resilience Testing
platform: android
id: MASTG-TEST-0245
type: [dynamic]
weakness: MASWE-0097
best-practices: []
---

## Overview

This test is designed to evaluate the effectiveness of root detection mechanisms. Its goal is to ensure that rooted devices are accurately identified so that any associated security risks can be addressed, ultimately safeguarding the integrity of the device and protecting user data.

The testing process involves running the app on a non-rooted and a rooted device to observe how the root detection mechanisms work. This includes monitoring system interactions, detecting access to root-specific files or binaries, and analyzing API calls commonly used for root detection. Additionally, various bypass techniques are tested to determine the robustness of the implemented security measures. It does so by dynamically analyzing the app binary for [common root detection checks](../../../Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#root-etection-and-common-root-detection-methods).

## Steps

1. **Prepare the test environment:**
   - Set up the non-rooted and rooted device to compare their behaviour.
2. **Run application which implements root detection on the non-rooted device:**
   - Verify that the detection works as expected.
3. **Monitor Application Behaviour:**
   - Use tools like strace or DDMS to trace what the app does when it checks for root. Look for interactions with the system, such as attempts to open su or check running processes. This will help you understand how the app is detecting root and might expose weaknesses in its implementation.
4. **Run the application on a rooted device:**
   - Check if root detection alerts appear.
5. **Test bypass techniques:**
   - Use tools like MagiskHide, RootCloak or UnRootBeer to see if root detection can be bypassed.
   - Experiment with techniques such as renaming binaries or using Frida/Xposed to hook into APIs.
6. **Analyze and report findings.**

## Observation

The main purpose of this test is to evaluate the accuracy of implemented root detection mechanisms. This means we want to see if the root detection mechanisms are effective at identifying devices that have been modified while minimizing instances where non-rooted devices are mistakenly flagged as rooted. The outcome should provide a comprehensive understanding of how effectively the application’s root detection mechanisms function. 

## Evaluation

The test passes if the root detection mechanisms successfully identify any signs of rooting on the device. The test is considered unsuccessful if a rooted device is not properly detected, if a non-rooted device is incorrectly flagged as rooted, or if any bypass technique allows complete circumvention of the detection mechanism.

To enhance the reliability of root detection, a combination of static and dynamic analysis methods should be used, such as checking system properties along with monitoring runtime behavior.
