---
platform: android
title: References to APIs and Permissions for Accessing External Storage
id: MASTG-TEST-0202
apis: [Environment#getExternalStoragePublicDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, MediaStore, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE]
type: [static]
weakness: MASWE-0007
profiles: [L1, L2]
---

## Overview

This test uses static analysis to look for uses of APIs allowing an app to write to locations that are shared with other apps (@MASTG-TEST-0001) such as the [external storage APIs](../../../0x05d-Testing-Data-Storage.md/#external-storage-apis) or the [`MediaStore` API](../../../0x05d-Testing-Data-Storage.md/#mediastore-api) as well as the relevant [Android manifest storage-related permissions](../../../0x05d-Testing-Data-Storage.md/#manifest-permissions).

This static test is great for identifying all code locations where the app is writing data to shared storage. However, it does not provide the actual data being written, and in some cases, the actual path in the device storage where the data is being written. Therefore, it is recommended to combine this test with others that take a dynamic approach, as this will provide a more complete view of the data being written to shared storage.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool on the reverse engineered app targeting calls to any external storage APIs and Android manifest storage permissions.

The static analysis tool should be able to identify all possible APIs and permissions used to write to shared storage, such as `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, `MediaStore`, `WRITE_EXTERNAL_STORAGE`, and `MANAGE_EXTERNAL_STORAGE`. See the [Android documentation](https://developer.android.com/training/data-storage/shared) for more information on these APIs and permissions.

## Observation

The output should contain a list of APIs and storage-related permissions used to write to shared storage and their code locations.

## Evaluation

The test case fails if:

- the app has the proper permissions declared in the Android manifest (e.g. `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, etc.)
- **and** the data being written to shared storage is sensitive and not encrypted.

To determine the latter, you may need to carefully review the reversed code (@MASTG-TECH-0023) and/or combine this test with others that take a dynamic approach, as this will provide a more complete view of the data being written to shared storage.

## References

- [Manage all files on a storage device](https://developer.android.com/training/data-storage/manage-all-files)
- [Access media files from shared storage](https://developer.android.com/training/data-storage/shared/media)
