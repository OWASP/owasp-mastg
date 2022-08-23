---
title: Check Databases

profiles:

static_keywords:
  - 

apis:
  -

locations:
  - /data/data/<package-name>/databases
  - /data/data/<package-name>/files/
---

## Overview

TBD

## Steps

- Determine whether SQLite databases are available and whether they contain sensitive information. SQLite databases are stored in `/data/data/<package-name>/databases`.
- Identify if SQLite databases are encrypted. If so, determine how the database password is generated and stored and if this is sufficiently protected as described in the "[Storing a Key](#storing-a-key)" section of the Keystore overview.

- Check for the usage of any Firebase Real-time databases and attempt to identify if they are misconfigured by making the following network call:
  - `https://_firebaseProjectName_.firebaseio.com/.json`
- Determine whether a Realm database is available in `/data/data/<package-name>/files/`, whether it is unencrypted, and whether it contains sensitive information. By default, the file extension is `realm` and the file name is `default`. Inspect the Realm database with the [Realm Browser](https://github.com/realm/realm-browser-osx "Realm Browser for macOS").

## Evaluation

TBD

## Mitigation

TBD
