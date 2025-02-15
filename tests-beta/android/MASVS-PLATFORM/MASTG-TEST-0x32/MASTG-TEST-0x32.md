---
platform: android
title: References to Content Provider Access in WebViews
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0x32
apis: [WebView, ContentProvider, allowContentAccess]
type: [static]
weakness: MASWE-0069
best-practices: []
---

## Overview

Many apps let users share media files with each other using [content providers](https://developer.android.com/guide/topics/providers/content-providers) (via `content://` URIs). For example, social media apps let users share photos and videos with friends. However, if a WebView in the app has access to content providers, an attacker could inject malicious JavaScript into the WebView to access these media files. This could lead to unauthorized access to sensitive media files stored on the device.

**Attack Scenario**

Suppose a banking app uses a WebView to display parts of its UI. The WebView is configured with setAllowContentAccess true. Due to another bug, an attacker is able to inject a JavaScript payload (for instance, via an XSS flaw on a remote help page). That payload then issues requests using content:// URIs to read locally stored files (which might include cached user credentials or transaction data) and sends that data to the attacker’s server. Even if the content provider is non‑exported, because the malicious code is running in the same process and same origin as the trusted code, it can access resources that normally wouldn’t be accessible from an external source.

**About the Test**

This test checks for references to Content Provider access in WebViews. Content Provider access allows WebViews to load content from a content provider installed on the system. This is enabled by default and can be disabled using the `setAllowContentAccess` method in the `WebSettings` class.

For an attacker to successfully exploit this vulnerability, they would need to inject malicious JavaScript into the WebView. This JavaScript could then access local resources, such as content from a content provider which may be giving access to resources from the app internal storage (sandbox), external app-specific storage (scoped storage), or external storage directories also accessible by other apps (media storage via the `MediaStore` content provider).

The JavaScript code would have access to any content provider on the device, including those declared by the app as not exported and others that are exported by other apps and may or may not be following the recommended [best practices](https://developer.android.com/privacy-and-security/security-tips#content-providers).

It is important to consider:

> [App attribution for media files (Android Developers)](https://developer.android.com/training/data-storage/shared/media#app-attribution):
> When [scoped storage](https://developer.android.com/training/data-storage#scoped-storage) is enabled for an app that targets Android 10 or higher, the system attributes an app to each media file, which determines the files that your app can access when it hasn't requested any storage permissions. Each file can be attributed to only one app. Therefore, if your app creates a media file that's stored in the photos, videos, or audio files media collection, your app has access to the file.
>
> If the user uninstalls and reinstalls your app, however, you must request [READ_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#READ_EXTERNAL_STORAGE) to access the files that your app originally created. This permission request is required because the system considers the file to be attributed to the previously installed version of the app, rather than the newly installed one.

Also:

> [Chromium WebView Docs](https://chromium.googlesource.com/chromium/src/%2B/HEAD/android_webview/docs/cors-and-webview-api.md#content_urls):
> `content://` URLs are used to access resources provided via Android Content Providers. The access should be permitted via `setAllowContentAccess` API beforehand. `content://` pages can contain iframes that load `content://` pages, but the parent frame can not access into the iframe contents. Also only `content://` pages can specify `content://` URLs for sub-resources.
>
> However, even pages loaded from `content://` can not make any [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)-enabled requests such as `XMLHttpRequest` to other `content://` URLs as each one is assumed to belong to an [opaque origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-opaque). See also `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs` sections as they can relax this default rule.
>
> Pages loaded with any scheme other than `content://` can't load `content://` page in iframes and they can not specify `content://` URLs for sub-resources.

### via XMLHttpRequest

For a JavaScript code to access a `content://` URI, e.g. `xhr.open("GET", "content://org.owasp.mastestapp.provider/sensitive.txt", true);`, not only `setAllowContentAccess` must be set to `true` but also `setAllowUniversalAccessFromFileURLs`. If this is not the case, the JavaScript code will fail independently of the `setAllowContentAccess` value and regardless the source being `file://` or `content://`.

```sh
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'content://org.owasp.mastestapp.provider/sensitive.txt' from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
```

An attacker who can inject JavaScript into a WebView might leverage the relaxed settings (or a misconfiguration) to read local sensitive files via the content provider. Even though Android’s default behavior prevents XMLHttpRequests from a content:// loaded page (due to opaque origin and CORS restrictions), loading the page from file:// with universal access enabled bypasses these restrictions. In a real attack, the injected JavaScript might send the sensitive data to an attacker-controlled server.

This demo illustrates why leaving content access enabled—and additionally relaxing origin restrictions—can be dangerous if an XSS or injection vulnerability is present.

### 

Note that `content://media/external_primary` works as long as the image "belongs" to the invoking app (due to `owner_package_name` attribute in the `MediaStore`). If the app calls a `content://` URI that does not belong to the app, it will fail with a `SecurityException`:

```sh
Cannot open content uri: content://media/external_primary/images/media/1000000041
java.lang.SecurityException: org.owasp.mastestapp has no access to content://media/external_primary/images/media/1000000041
```

You can validate this by querying the MediaStore via adb, for example:

- `adb shell content query --uri content://media/external_primary/images/media`
- `adb shell content query --uri content://media/external_primary/file`

To be able to access the content, the app must have the necessary permissions e.g., `READ_EXTERNAL_STORAGE` before Android 10 API level 29, `READ_MEDIA_IMAGES` or `MANAGE_EXTERNAL_STORAGE` from Android 10 API level 29 onwards.

> READ_EXTERNAL_STORAGE is deprecated (and is not granted) when targeting Android 13+ API level 33. If you need to query or interact with MediaStore or media files on the shared storage, you should instead use one or more new storage permissions: READ_MEDIA_IMAGES, READ_MEDIA_VIDEO or READ_MEDIA_AUDIO.
>
> Scoped storage is enforced on Android 10+ API level 29+ (or Android 11+ if using requestLegacyExternalStorage). In particular, WRITE_EXTERNAL_STORAGE will no longer provide write access to all files; it will provide the equivalent of READ_EXTERNAL_STORAGE instead.
>
> As of Android 13 API level 33, if you need to query or interact with MediaStore or media files on the shared storage, you should be using instead one or more new storage permissions: READ_MEDIA_IMAGES, READ_MEDIA_VIDEO or READ_MEDIA_AUDIO.

After declaring the permission in the manifest you can grant it with adb:

```sh
adb shell pm grant org.owasp.mastestapp android.permission.READ_MEDIA_IMAGES
```

You can revoke the permission with:

```sh
adb shell pm revoke org.owasp.mastestapp android.permission.READ_MEDIA_IMAGES
```

The provider must also be declared with `android:grantUriPermissions="true"` in the manifest. This is necessary because the provider is not exported, and the app must have the necessary permissions to access the content.

### via <img> element

An attacker could try to read the <img> data after it's laoded using the `canvas` element, but this would also fail due to the SOP (Same Origin Policy) restrictions:

```html
<--! In the HTML, an <img> element with id "internalImage" loads the image via its content:// URI. Once the image is loaded, JavaScript creates a canvas, draws the image into it, and then extracts a data URL using canvas.toDataURL("image/png"). The resulting string is then inserted into the <div> with id "output". -->

<script type="text/javascript">
    function readImageData() {
    var img = document.getElementById("internalImage");
    var canvas = document.createElement("canvas");
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    var ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0);
    try {
        var dataUrl = canvas.toDataURL("image/png");
        document.getElementById("output").innerText = dataUrl;
    } catch(e) {
        document.getElementById("output").innerText = "Error reading image data: " + e.message;
    }
    }
    
    window.onload = function() {
    var img = document.getElementById("internalImage");
    if (img.complete) {
        readImageData();
    } else {
        img.onload = readImageData;
    }
    };
</script>
...
<body>
    <img id="internalImage" style="width: 10em" src="content://org.owasp.mastestapp.provider/logo_circle.png" alt="Internal Storage Image">
```

```sh
error reading image data: failed to execute todataurl on HTMLcanvaselement: tainted canvases may not be exported
```

Unfortunately, when loading an image from a content:// URI via a non‑exported content provider, the WebView does not supply the necessary CORS headers. Even with the crossorigin="anonymous" attribute, the image remains “tainted” because the response isn’t sending an appropriate Access-Control header.

Without intercepting the request (or otherwise serving the image from a source that provides the proper CORS header), there isn’t a way in plain JavaScript to “un-taint” the canvas. In other words, if you must rely solely on JavaScript (and not use shouldInterceptRequest or a server that provides CORS headers), the browser’s security model will prevent you from reading the canvas data.

### via shouldInterceptRequest

## Steps

1. Use a tool like semgrep to search for references to the `setAllowContentAccess` method in the `WebSettings` class.

## Observation

The output should contain a list of locations where:

- the `setAllowContentAccess` method is used and explicitly set to `true`.
- the `setAllowContentAccess` method is used and explicitly set to `false`.
- the `setAllowContentAccess` method is not used and the default value, `true`, is assumed.

## Evaluation

The test fails if the `setAllowContentAccess` method is used and explicitly set to `true` or if the default value is assumed.

The test passes if the `setAllowContentAccess` method is used and explicitly set to `false`.

**Should I report this issue?**

Why Report It?

- Defense in Depth: Even if the immediate impact seems limited (for example, images alone might not yield secret data), leaving content access enabled increases the number of ways an attacker might chain vulnerabilities.
- Combined Vulnerabilities: On its own, setAllowContentAccess may not lead to a full compromise, but if combined with an XSS or other injection vulnerability (or if the WebView is used to display untrusted remote content), an attacker might be able to leverage the ability to load local files.
- Misconfiguration Risk: In some cases, developers enable additional settings (like allowing file access or universal access from file URLs) that, together with setAllowContentAccess, further widen the attack surface.

Even though there are many “safeguards” (such as CORS restrictions and the fact that a non‑exported provider won’t serve data to an arbitrary external caller), leaving content access enabled in a WebView can still enlarge the attack surface in a “chain‐of‐vulnerabilities” scenario.

Having content access enabled in a WebView is not a vulnerability per se, but it can chained with other vulnerabilities, for example:

- cross‑site scripting (XSS)
- universal file access

If the injected code succeeds in reading sensitive data (for example, by fetching text or HTML content that is then rendered and exfiltrated via an HTTP request), the attacker can send that data back to a remote server.

Mitigations include:

- Setting `setAllowContentAccess` to `false` to prevent the WebView from accessing content providers.
- Ensuring file-based access is disabled by explicitly setting `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, and `setAllowUniversalAccessFromFileURLs` to `false`. Or, depending on the Android version, relying on the default values.
- Using [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) to load assets from the app's assets directory instead of using `file:///android_asset` URLs.
