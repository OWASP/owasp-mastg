---
title: Frida CodeShare
platform: generic
source: https://codeshare.frida.re/
---

[Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") is a repository containing a collection of ready-to-run Frida scripts which can enormously help when performing concrete tasks both on Android as on iOS as well as also serve as inspiration to build your own scripts. Some examples of useful scripts:

- Frida Multiple Unpinning - <https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/>
- Disable Flutter TLS verification - <https://codeshare.frida.re/@TheDauntless/disable-flutter-tls-v1/>
- ObjC method observer - <https://codeshare.frida.re/@mrmacete/objc-method-observer/>
- JNI Trace - <https://codeshare.frida.re/@chame1eon/jnitrace/>
- Dump dynamically loaded DEX - <https://codeshare.frida.re/@cryptax/inmemorydexclassloader-dump/>
- Enable iOS WebInspector - <https://codeshare.frida.re/@leolashkevych/ios-enable-webinspector/>

Using them is as simple as including the `--codeshare <script>` flag with the chosen script when using the Frida CLI. For example, to use "ObjC method observer", enter the following:

```bash
frida --codeshare mrmacete/objc-method-observer -f YOUR_BINARY
```
