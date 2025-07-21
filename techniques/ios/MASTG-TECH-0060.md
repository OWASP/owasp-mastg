---
title: Monitoring System Logs
platform: ios
---

Many apps log informative (and potentially sensitive) messages to the console log. The log also contains crash reports and other useful information. You can collect console logs through multiple methods:

## Using @MASTG-TOOL-0070

1. Launch Xcode.
2. Connect your device to your host computer.
3. Choose **Window** -> **Devices and Simulators**.
4. Click on your connected iOS device in the left section of the Devices window.
5. Reproduce the problem.
6. Click on the **Open Console** button located in the upper right-hand area of the Devices window to view the console logs on a separate window.

<img src="Images/Chapters/0x06b/open_device_console.png" width="100%" />

To save the console output to a text file, go to the top right side of the Console window and click on the **Save** button.

<img src="Images/Chapters/0x06b/device_console.png" width="100%" />

## Using @MASTG-TOOL-0126

1. Connect your device to your host computer
2. Run`idevicesyslog` in your terminal

<img src="Images/Chapters/0x06b/open_device_console.png" width="100%" />
