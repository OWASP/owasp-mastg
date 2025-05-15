--- 
title: Inspecting an App's Backup Data
platform: android 
---

You can inspect an Android app's backup data to verify that sensitive data is not included in the backup. This technique is useful for verifying that the app correctly excludes sensitive data from backups.

## Backup Made via ADB Backup

Android backups are stored in `.ab` files, which are specially formatted TAR archives. If you followed the steps from @MASTG-TECH-0128, you should have an `apps/` directory in your working directory. This directory contains the extracted backup data.

The files are stored within top-level directories according to their semantic origin:

- `apps/pkgname/a/`: Application .apk file itself
- `apps/pkgname/obb/`: The application's associated .obb containers
- `apps/pkgname/f/`: The subtree rooted at the `getFilesDir()` location
- `apps/pkgname/db/`: The subtree rooted at the `getDatabasePath()` parent
- `apps/pkgname/sp/`: The subtree rooted at the `getSharedPrefsFile()` parent
- `apps/pkgname/r/`: Files stored relative to the root of the app's file tree
- `apps/pkgname/c/`: Reserved for the app's `getCacheDir()` tree; not stored.
