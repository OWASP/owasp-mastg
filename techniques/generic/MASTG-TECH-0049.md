---
title: Dynamic Analysis
platform: generic
---

Dynamic Analysis tests the mobile app by executing and running the app binary and analyzing its workflows for vulnerabilities. For example, vulnerabilities regarding data storage might be sometimes hard to catch during static analysis, but in dynamic analysis you can easily spot what information is stored persistently and if the information is protected properly. Besides this, dynamic analysis allows the tester to properly identify:

- Business logic flaws
- Vulnerabilities in the tested environments
- Improper input validation and bad input/output encoding as they are processed through one or multiple services

Analysis can be assisted by automated tools, such as @MASTG-TOOL-0035, while assessing an application. An application can be assessed by side-loading it, re-packaging it, or by simply attacking the installed version.

## Basic Information Gathering

As mentioned previously, Android runs on top of a modified Linux kernel and retains the [proc filesystem](https://www.kernel.org/doc/Documentation/filesystems/proc.txt "procfs") (procfs) from Linux, which is mounted at `/proc`. Procfs provides a directory-based view of a process running on the system, providing detailed information about the process itself, its threads, and other system-wide diagnostics. Procfs is arguably one of the most important filesystems on Android, where many OS native tools depend on it as their source of information.

Many command line tools are not shipped with the Android firmware to reduce the size, but can be easily installed on a rooted device using @MASTG-TOOL-0013. We can also create our own custom scripts using commands like `cut`, `grep`, `sort` etc, to parse the proc filesystem information.

In this section, we will be using information from procfs directly or indirectly to gather information about a running process.
