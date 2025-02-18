---
title: Missing Certificate Pinning in Network Traffic
platform: network
id: MASTG-TEST-0x242
type: [static]
weakness: MASWE-0047
---

## Overview

There are various ways how certificate pinning can be done for an application.

Since statically finding all of the locations where certificate pinning is performed might not be feasible, this test case uses dynamic analysis to observe all connections the app makes.

The goal of this test case is to dynamically check if the connection to a server can be intercepted using a [Man-in-the-Middle attack]("../../../Document/0x04f-Testing-Network-Communication.md#mitm-attack). If this is possible, it means that the certificate is not pinned correctly or not pinned at all.

## Steps

1. Set up an intercepting proxy, for example @MASTG-TOOL-0077 or @MASTG-TOOL-0097.
2. Install the application on a device connected to that proxy, and intercept the communication.
3. Extract all domains which were intercepted.

## Observation

The output should contain a list domains, for which the interception was successful.

## Evaluation

The test case fails if any relevant domain was intercepted.
