---
title: Check the App Binary
profiles:

static_keywords:
  - MODE_WORLD_READABLE
  - MODE_WORLD_WRITABLE

apis:
  - SharedPreferences
  - FileOutPutStream
  - getExternal*
  - getWritableDatabase
  - getReadableDatabase
  - getCacheDir

locations:
  - 

---

## Overview

TBD

## Steps

Check the source code for keywords and API calls that are used to store data:

- File permissions, such as:
  - `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`: You should avoid using `MODE_WORLD_WRITEABLE` and `MODE_WORLD_READABLE` for files because any app will be able to read from or write to the files, even if they are stored in the app's private data directory. If data must be shared with other applications, consider a content provider. A content provider offers read and write permissions to other apps and can grant dynamic permission on a case-by-case basis.

- Classes and functions, such as:
  - the `SharedPreferences` class ( stores key-value pairs)
  - the `FileOutPutStream` class (uses internal or external storage)
  - the `getExternal*` functions (use external storage)
  - the `getWritableDatabase` function (returns a SQLiteDatabase for writing)
  - the `getReadableDatabase` function (returns a SQLiteDatabase for reading)
  - the `getCacheDir` and `getExternalCacheDirs` function (use cached files)

## Evaluation

TBD

## Mitigation

TBD
