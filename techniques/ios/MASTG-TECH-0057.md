---
title: Listing Installed Apps
platform: ios
---

When targeting apps that are installed on the device, you'll first have to figure out the correct bundle identifier of the application you want to analyze. You can use `frida-ps -Uai` to get all apps (`-a`) currently installed (`-i`) on the connected USB device (`-U`):

```bash
$ frida-ps -Uai
 PID  Name                 Identifier
----  -------------------  -----------------------------------------
6853  iGoat-Swift          OWASP.iGoat-Swift
6847  Calendar             com.apple.mobilecal
6815  Mail                 com.apple.mobilemail
   -  App Store            com.apple.AppStore
   -  Apple Store          com.apple.store.Jolly
   -  Calculator           com.apple.calculator
   -  Camera               com.apple.camera
```

It also shows which of them are currently running (@MASTG-APP-0028 for example). Take a note of the "Identifier" (bundle identifier: `OWASP.iGoat-Swift`) and the PID (`6853`) as you'll need them for further analysis.

You can also directly open @MASTG-TOOL-0061 and after selecting your iOS device you'll get the list of installed apps.

<img src="Images/Chapters/0x06b/grapefruit_installed_apps.png" width="400px" />
