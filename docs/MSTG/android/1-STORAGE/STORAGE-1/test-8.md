---
title: Check File Permissions
profiles:

static_keywords:
  - 

apis:
  -

locations:
  - /data/data/<package-name>
---

## Overview

TBD

## Steps

Check the permissions of the files in `/data/data/<package-name>`.

## Evaluation

Only the user and group created when you installed the app (e.g., u0_a82) should have user read, write, and execute permissions (`rwx`). Other users should not have permission to access files, but they may have execute permissions for directories.

## Mitigation

TBD
