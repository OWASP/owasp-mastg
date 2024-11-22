---
title: Detection of RASP presence in mobile application 
platform: android
id: MASTG-TEST-0228
type: [static, dynamic]
available_since: 24
weakness: MASWE-0103
mitigations:
prerequisities: 
---

## Overview
RASP (Runtime Application Self-Protection) is designed to monitor and protect the application during runtime by detecting and responding to threats in real-time.  The test verifies if the application can identify and react to unauthorised modifications, such as code tampering, root or jailbreak environment, and attempts to bypass security mechanisms. It also checks if the application has the ability to protect sensitive data and prevent unauthorised access to critical operations or features.

By conducting this test, we ensure that the app is capable of defending against runtime attacks and maintaining its integrity even in compromised environments. If RASP techniques are not implemented or are improperly configured, the app may be vulnerable to various security threats, including data breaches, unauthorised access, and malicious modifications.

## Steps
1. Ensure that all security checks and protection mechanisms expected from RASP are present and enabled with the application. To test the RASP policy that the app enforces, a written copy of the policy must be provided. The policy should define available checks and their enforcement. For example: 
   - Root detection.
   - Screen lock enforcement.
   - Code integrity checks.
   - Detection of dynamic analysis.

2. Based on the previous step, attempt to simulate threats to test if the application reacts as expected. This can involve various scenarios such as:
   - Launching the mobile application on a rooted device.
   - Launching the mobile application on a device without a screen lock enabled.
   - Attempting to repackage the application and launching it.
   - Launching the application in an emulator.
  
3. Verify that the application properly detects and responds to potential threats. There are various scenarios in which a mobile application can respond to these threats, such as:
   - Killing the app.
   - Warning the user about the detected threat.
   - Logging information about potential risks to a database or SIEM.

## Observation
The output depends on the specific reactions set up for the mobile application. The results should demonstrate the app’s behaviour when a threat is detected or triggered, for example:
- Application is terminated.
- Application displays a warning message.
- Application sends information to a database or SIEM. Testers should ensure that the collected threat intelligence data are rich enough.


## Evaluation
The test case fails if the mobile application does not react as expected to the detected threats.
