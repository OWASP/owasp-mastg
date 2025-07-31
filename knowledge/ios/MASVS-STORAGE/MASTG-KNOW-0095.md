---
masvs_category: MASVS-STORAGE
platform: ios
title: Firebase Real-time Databases
---

Firebase is a development platform with more than 15 products, and one of them is Firebase Real-time Database. It can be leveraged by application developers to store and sync data with a NoSQL cloud-hosted database. The data is stored as JSON and is synchronized in real-time to every connected client and also remains available even when the application goes offline.

A misconfigured Firebase instance can be identified by making the following network call:

`https://\<firebaseProjectName\>.firebaseio.com/.json`

The _firebaseProjectName_ can be retrieved from the property list(.plist) file. For example, `PROJECT_ID` key stores the corresponding Firebase project name in _GoogleService-Info.plist_ file.

Alternatively, the analysts can use [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner "Firebase Scanner"), a python script that automates the task above as shown below:

```bash
python FirebaseScanner.py -f <commaSeparatedFirebaseProjectNames>
```
