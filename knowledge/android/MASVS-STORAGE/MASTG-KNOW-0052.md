---
masvs_category: MASVS-STORAGE
platform: android
title: User Interface Components
---

At certain points in time, the user will have to enter sensitive information into the application. This data may be financial information such as credit card data or user account passwords, or maybe healthcare data. The data may be exposed if the app doesn't properly mask it while it is being typed.

In order to prevent disclosure and mitigate risks such as [shoulder surfing](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29) you should verify that no sensitive data is exposed via the user interface unless explicitly required (e.g. a password being entered). For the data required to be present it should be properly masked, typically by showing asterisks or dots instead of clear text.
