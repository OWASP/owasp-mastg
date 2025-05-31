---
title: Platform-provided Authentication APIs Not Used
id: MASWE-0032
alias: platform-auth-apis
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-1, MASVS-CODE-3]
  cwe: [287]

refs:
- https://developer.android.com/privacy-and-security/security-tips#Credentials
- https://developer.apple.com/documentation/security/password_autofill
- https://developer.apple.com/videos/play/wwdc2017/206
- https://developer.android.com/guide/topics/text/autofill-optimize
draft:
  description: AKA don't roll your own authentication security. Platform-provided
    APIs are designed and implemented by experts who have deep knowledge of the platform's
    security features and considerations. These APIs often incorporate security best
    practices and are regularly updated to address new threats and vulnerabilities.
    Not using platform-provided authentication APIs in mobile apps can result in security
    vulnerabilities, inconsistent user experience, missed integration opportunities,
    and increased development and maintenance efforts.
  topics:
  - credential auto-fill to avoid copy/paste
  - correct use of Android AccountManager (e.g. invoke a cloud-based service and don't
    store passwords on the device). AccountManager data stored in clear in some Android
    versions.
  - use of CREATOR afterretrieving an account with AccountManager
  - use of Authentication Services framework on iOS
  - iOS Password AutoFill streamlines logging into web services at your domain. However,
    if you need to log into a third-party service, use ASWebAuthenticationSession
    instead
status: placeholder

---

