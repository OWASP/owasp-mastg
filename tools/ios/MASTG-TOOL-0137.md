---
title: GlobalWebInspect
platform: ios
source: https://github.com/ChiChou/GlobalWebInspect
host:
- ios
---

!!! warning

    This tool may or may not work depending on your macOS / iOS combination.

GlobalWebInspect can be installed on a jailbroken iOS device to enable web-inspection on any WebView in any application. The tweak can be installed by copying it over to your device and using `sudo dpkg -i <file>`.

To activate the web inspection you have to follow these steps:

1. On the iOS device open the Settings app: Go to **Safari -> Advanced** and toggle on _Web Inspector_.
2. On the macOS device, open Safari: in the menu bar, go to **Safari -> Preferences -> Advanced** and enable _Show Develop menu in menu bar_.
3. Connect your iOS device to the macOS device and unlock it: the iOS device name should appear in the _Develop_ menu.
4. (If not yet trusted) On macOS's Safari, go to the _Develop_ menu, click on the iOS device name, then on "Use for Development" and enable trust.

To open the web inspector and debug a WebView:

1. In iOS, open the app and navigate to the screen that should contain a WebView.
2. In macOS Safari, go to **Developer -> 'iOS Device Name'** and you should see the name of the WebView based context. Click on it to open the Web Inspector.

Now you're able to debug the WebView as you would with a regular web page on your desktop browser.

![Enable Developer settings](Images/Tools/TOOL-0137-safari-dev.png)

If everything is set up correctly, you can attach to WKWebViews with Safari:

![Attaching to a webview](Images/Tools/TOOL-0137-attach-webview.png)

![Safari Web Inspector](Images/Tools/TOOL-0137-web-inspector.png)