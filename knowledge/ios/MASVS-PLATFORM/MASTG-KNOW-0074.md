---
masvs_category: MASVS-PLATFORM
platform: ios
title: Enforced Updating
---

Enforced updating can be helpful when it comes to public key pinning (see the Testing Network communication for more details) when a pin has to be refreshed due to a certificate/public key rotation. Additionally, vulnerabilities are easily patched by means of forced updates.

The challenge with iOS however, is that Apple does not provide any APIs yet to automate this process, instead, developers will have to create their own mechanism, such as described at various [blogs](https://mobikul.com/show-update-application-latest-version-functionality-ios-app-swift-3/ "Updating version in Swift 3") which boil down to looking up properties of the app using `http://itunes.apple.com/lookup\?id\<BundleId>` or third party libraries, such as [Siren](https://github.com/ArtSabintsev/Siren "Siren") and [react-native-appstore-version-checker](https://www.npmjs.com/package/react-native-appstore-version-checker "Update checker for React"). Most of these implementations will require a certain given version offered by an API or just "latest in the appstore", which means users can be frustrated with having to update the app, even though no business/security need for an update is truly there.

Please note that newer versions of an application will not fix security issues that are living in the backends to which the app communicates. Allowing an app not to communicate with it might not be enough. Having proper API-lifecycle management is key here.
Similarly, when a user is not forced to update, do not forget to test older versions of your app against your API and/or use proper API versioning.
