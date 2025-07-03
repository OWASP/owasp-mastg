---
title: Hiding sensitive content from screenshots before backgrounding
alias: hiding-sensitive-content-from-screenshots-before-backgrounding
id: MASTG-BEST-0016
platform: ios
---

Ensure that the app hides sensitive content, such as credit card details and passcodes, before entering the background state. The system takes a screenshot of the current app's view and stores it on the disk. An attacker may extract this screenshot from there. You can find more details at @KNO

Refer to the "[Testing Data Storage](../../Document/0x06d-Testing-Data-Storage.md "Testing Data Storage")" chapter for more information and best practices on securely storing sensitive data.
