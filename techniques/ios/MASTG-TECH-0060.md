---
title: Monitoring System Logs
platform: ios
---

Many apps log informative (and potentially sensitive) messages to the console log. The log also contains crash reports and other useful information. You can collect console logs through the Xcode **Devices** window as follows:

1. Launch Xcode.
2. Connect your device to your host computer.
3. Choose **Window** -> **Devices and Simulators**.
4. Click on your connected iOS device in the left section of the Devices window.
5. Reproduce the problem.
6. Click on the **Open Console** button located in the upper right-hand area of the Devices window to view the console logs on a separate window.

<img src="Images/Chapters/0x06b/open_device_console.png" width="100%" />

To save the console output to a text file, go to the top right side of the Console window and click on the **Save** button.

<img src="Images/Chapters/0x06b/device_console.png" width="100%" />

You can also connect to the device shell as explained in [Accessing the Device Shell](0x06b-iOS-Security-Testing.md#accessing-the-device-shell), install socat via apt-get and run the following command:

```bash
iPhone:~ root# socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock

========================
ASL is here to serve you
> watch
OK

Jun  7 13:42:14 iPhone chmod[9705] <Notice>: MS:Notice: Injecting: (null) [chmod] (1556.00)
Jun  7 13:42:14 iPhone readlink[9706] <Notice>: MS:Notice: Injecting: (null) [readlink] (1556.00)
Jun  7 13:42:14 iPhone rm[9707] <Notice>: MS:Notice: Injecting: (null) [rm] (1556.00)
Jun  7 13:42:14 iPhone touch[9708] <Notice>: MS:Notice: Injecting: (null) [touch] (1556.00)
...
```

Additionally, Passionfruit offers a view of all the NSLog-based application logs. Simply click on the **Console** -> **Output** tab:

<img src="Images/Chapters/0x06b/passionfruit_console_logs.png" width="100%" />
