---
masvs_v1_id:
- MSTG-PLATFORM-10
masvs_v2_id:
- MASVS-PLATFORM-2
platform: android
title: Testing WebViews Cleanup
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

To test for [WebViews cleanup](../../../Document/0x05h-Testing-Platform-Interaction.md#webviews-cleanup "WebViews Cleanup") you should inspect all APIs related to WebView data deletion and try to fully track the data deletion process.

## Static Analysis

Start by identifying the usage of the following WebView APIs and carefully validate the mentioned best practices.

- **Initialization**: an app might be initializing the WebView in a way to avoid storing certain information by using `setDomStorageEnabled`, `setAppCacheEnabled` or `setDatabaseEnabled` from [`android.webkit.WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings "WebSettings"). The DOM Storage (for using the HTML5 local storage), Application Caches and Database Storage APIs are disabled by default, but apps might set these settings explicitly to "true".

- **Cache**: Android's WebView class offers the [`clearCache`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean) "clearCache in WebViews") method which can be used to clear the cache for all WebViews used by the app. It receives a boolean input parameter (`includeDiskFiles`) which will wipe all stored resource including the RAM cache. However if it's set to false, it will only clear the RAM cache. Check the app for usage of the `clearCache` method and verify its input parameter. Additionally, you may also check if the app is overriding `onRenderProcessUnresponsive` for the case when the WebView might become unresponsive, as the `clearCache` method might also be called from there.

- **WebStorage APIs**: [`WebStorage.deleteAllData`](https://developer.android.com/reference/android/webkit/WebStorage#deleteAllData) can be also used to clear all storage currently being used by the JavaScript storage APIs, including the Web SQL Database and the HTML5 Web Storage APIs.
  > Some apps will _need_ to enable the DOM storage in order to display some HTML5 sites that use local storage. This should be carefully investigated as this might contain sensitive data.

- **Cookies**: any existing cookies can be deleted by using [CookieManager.removeAllCookies](https://developer.android.com/reference/android/webkit/CookieManager#removeAllCookies(android.webkit.ValueCallback%3Cjava.lang.Boolean%3E)).

- **File APIs**: proper data deletion in certain directories might not be that straightforward, some apps use a pragmatic solution which is to _manually_ delete selected directories known to hold user data. This can be done using the `java.io.File` API such as [`java.io.File.deleteRecursively`](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.io/java.io.-file/delete-recursively.html).

**Example:**

This example in Kotlin from the [open source Firefox Focus](https://github.com/mozilla-mobile/focus-android/blob/v8.17.1/app/src/main/java/org/mozilla/focus/webview/SystemWebView.kt#L220 "Firefox Focus for Android") app shows different cleanup steps:

```Java
override fun cleanup() {
    clearFormData() // Removes the autocomplete popup from the currently focused form field, if present. Note this only affects the display of the autocomplete popup, it does not remove any saved form data from this WebView's store. To do that, use WebViewDatabase#clearFormData.
    clearHistory()
    clearMatches()
    clearSslPreferences()
    clearCache(true)

    CookieManager.getInstance().removeAllCookies(null)

    WebStorage.getInstance().deleteAllData() // Clears all storage currently being used by the JavaScript storage APIs. This includes the Application Cache, Web SQL Database and the HTML5 Web Storage APIs.

    val webViewDatabase = WebViewDatabase.getInstance(context)
    // It isn't entirely clear how this differs from WebView.clearFormData()
    @Suppress("DEPRECATION")
    webViewDatabase.clearFormData() // Clears any saved data for web forms.
    webViewDatabase.clearHttpAuthUsernamePassword()

    deleteContentFromKnownLocations(context) // calls FileUtils.deleteWebViewDirectory(context) which deletes all content in "app_webview".
}
```

The function finishes with some extra _manual_ file deletion in `deleteContentFromKnownLocations` which calls functions from [`FileUtils`](https://github.com/mozilla-mobile/focus-android/blob/v8.17.1/app/src/main/java/org/mozilla/focus/utils/FileUtils.kt). These functions use the [`java.io.File.deleteRecursively`](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.io/java.io.-file/delete-recursively.html) method to recursively delete files from the specified directories.

```Java
private fun deleteContent(directory: File, doNotEraseWhitelist: Set<String> = emptySet()): Boolean {
    val filesToDelete = directory.listFiles()?.filter { !doNotEraseWhitelist.contains(it.name) } ?: return false
    return filesToDelete.all { it.deleteRecursively() }
}
```

## Dynamic Analysis

Open a WebView accessing sensitive data and then log out of the application. Access the application's storage container and make sure all WebView related files are deleted. The following files and folders are typically related to WebViews:

- app_webview
- Cookies
- pref_store
- blob_storage
- Session Storage
- Web Data
- Service Worker
