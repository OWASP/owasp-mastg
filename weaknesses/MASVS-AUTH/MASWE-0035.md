---
title: Passwordless Authentication Not Implemented
id: MASWE-0035
alias: no-passwordless-auth
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-1, MASVS-STORAGE-1]
  cwe: [287]

refs:
- https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication
- https://www.w3.org/TR/webauthn-2/
- https://fidoalliance.org/white-paper-multi-device-fido-credentials/
- https://developers.google.com/identity/fido
- https://developers.google.com/identity/fido#what_are_passkeys
- https://fidoalliance.org/developers/
- https://fidoalliance.org/product-category/android-client/
- https://fidoalliance.org/product-category/ios-client/
- https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication/supporting_passkeys
- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/expansion-of-fido-standard-and-new-updates-for-microsoft/ba-p/3290633
- https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication/supporting_security_key_authentication_using_physical_keys
- https://developer.apple.com/videos/play/wwdc2021/10106/
draft:
  description: there's no use of passwordless authentication mechanisms e.g. passkeys
  topics:
  - passkeys or multi-device FIDO credentials
  - WebAuthn/ASAuthorization
  - use of Physical Security Keys which stored the public-private key pair on a physical
    medium, such as a security card or a USB key
status: placeholder

---

