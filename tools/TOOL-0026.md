---
title: gplaycli
platform: android
refs:
  - https://github.com/matlink/gplaycli
---

[gplaycli](https://github.com/matlink/gplaycli "gplaycli") is a Python based CLI tool to search, install and update Android applications from the Google Play Store. Follow the [installation steps](https://github.com/matlink/gplaycli#installation "gplaycli Installation") and you're ready to run it. gplaycli offers several options, please refer to its help (`-h`) for more information.

If you're unsure about the package name (or AppID) of an app, you may perform a keyword based search for APKs (`-s`):

```bash
$ gplaycli -s "google keep"

Title                          Creator     Size      Last Update  AppID                                    Version

Google Keep - notes and lists  Google LLC  15.78MB   4 Sep 2019   com.google.android.keep                  193510330
Maps - Navigate & Explore      Google LLC  35.25MB   16 May 2019  com.google.android.apps.maps             1016200134
Google                         Google LLC  82.57MB   30 Aug 2019  com.google.android.googlequicksearchbox  301008048
```

> Note that regional (Google Play) restrictions apply when using gplaycli. In order to access apps that are restricted in your country you can use alternative app stores such as the ones described in "[Alternative App Stores](#alternative-app-stores "Alternative App Stores")".
