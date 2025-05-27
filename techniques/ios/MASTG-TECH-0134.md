---
title: Monitoring the Pasteboard
platform: ios
---

You can monitor the pasteboard to check for sensitive data being copied to it. This is useful for detecting potential data leaks or misuse of the pasteboard in iOS applications.

## Getting Pasteboard Information

- Obtain the pasteboard name by hooking `pasteboardWithName:create:` and inspecting its input parameters, or `pasteboardWithUniqueName` and inspecting its return value.
- Get the first available pasteboard item: e.g., for strings, use the `string` method. Alternatively, use any of the other methods for the [standard data types](https://developer.apple.com/documentation/uikit/uipasteboard?language=objc#1654275 "Getting and Setting Pasteboard Items of Standard Data Types").
- Get the number of items with `numberOfItems`.
- Check for the existence of standard data types with the [convenience methods](https://developer.apple.com/documentation/uikit/uipasteboard?language=objc#2107142 "Checking for Data Types on a Pasteboard"), e.g., `hasImages`, `hasStrings`, `hasURLs` (starting in iOS 10).
- Check for other data types (typically UTIs) with [`containsPasteboardTypes: inItemSet:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622100-containspasteboardtypes?language=objc "UIPasteboard containsPasteboardTypes:inItemSet:"). You may inspect more concrete data types like, for example, a picture as public.png and public.tiff ([UTIs](http://web.archive.org/web/20190616231857/https://developer.apple.com/documentation/mobilecoreservices/uttype "MobileCoreServices UTType")) or for custom data such as com.mycompany.myapp.mytype. Remember that, in this case, only those apps that _declare knowledge_ of the type are able to understand the data written to the pasteboard. This is the same as we have seen in the [UIActivity Sharing](../../Document/0x06h-Testing-Platform-Interaction.md#uiactivity-sharing "UIActivity Sharing") section. Retrieve them using [`itemSetWithPasteboardTypes:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622071-itemsetwithpasteboardtypes?language=objc "UIPasteboard itemSetWithPasteboardTypes:") and setting the corresponding UTIs.
- Check for excluded or expiring items by hooking `setItems:options:` and inspecting its options for `UIPasteboardOptionLocalOnly` or `UIPasteboardOptionExpirationDate`.

## Monitoring Sensitive Data

If only looking for strings, you may want to use the command `ios pasteboard monitor` from @MASTG-TOOL-0074:

> Hooks into the iOS UIPasteboard class and polls the generalPasteboard every 5 seconds for data. If new data is found, different from the previous poll, that data will be dumped to the screen.

You may also build your own pasteboard monitor that monitors specific information as seen above.

For example, this script (inspired by the script behind [objection's pasteboard monitor](https://github.com/sensepost/objection/blob/b39ee53b5ba2e9a271797d2f3931d79c46dccfdb/agent/src/ios/pasteboard.ts "pasteboard.ts")) reads the pasteboard items every 5 seconds. If there's something new, it will print it:

```javascript
const UIPasteboard = ObjC.classes.UIPasteboard;
    const Pasteboard = UIPasteboard.generalPasteboard();
    var items = "";
    var count = Pasteboard.changeCount().toString();

setInterval(function () {
      const currentCount = Pasteboard.changeCount().toString();
      const currentItems = Pasteboard.items().toString();

      if (currentCount === count) { return; }

      items = currentItems;
      count = currentCount;

      console.log('[* Pasteboard changed] count: ' + count +
      ' hasStrings: ' + Pasteboard.hasStrings().toString() +
      ' hasURLs: ' + Pasteboard.hasURLs().toString() +
      ' hasImages: ' + Pasteboard.hasImages().toString());
      console.log(items);

    }, 1000 * 5);
```

In the output, we can see the following:

```bash
[* Pasteboard changed] count: 64 hasStrings: true hasURLs: false hasImages: false
(
    {
        "public.utf8-plain-text" = hola;
    }
)
[* Pasteboard changed] count: 65 hasStrings: true hasURLs: true hasImages: false
(
    {
        "public.url" = "https://codeshare.frida.re/";
        "public.utf8-plain-text" = "https://codeshare.frida.re/";
    }
)
[* Pasteboard changed] count: 66 hasStrings: false hasURLs: false hasImages: true
(
    {
        "com.apple.uikit.image" = "<UIImage: 0x1c42b23c0> size {571, 264} orientation 0 scale 1.000000";
        "public.jpeg" = "<UIImage: 0x1c44a1260> size {571, 264} orientation 0 scale 1.000000";
        "public.png" = "<UIImage: 0x1c04aaaa0> size {571, 264} orientation 0 scale 1.000000";
    }
)
```

You see that first a text was copied, including the string `"hola"`. After that, a URL was copied, and finally, a picture was copied. Some of them are available via different UTIs. Other apps will consider these UTIs to allow pasting of this data or not.
