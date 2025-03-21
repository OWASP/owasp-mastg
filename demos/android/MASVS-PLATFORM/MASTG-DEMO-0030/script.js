// Configuration parameter:
// Set to true to wait for the first call to getSettings() before enumerating WebViews.
// Set to false to enumerate immediately.
var delayEnumerationUntilGetSettings = true;

Java.perform(function() {
  var seenWebViews = {};
  var internalCall = false; // Flag to indicate internal calls

  // Function to print backtrace with a configurable number of lines (default: 5)
  function printBacktrace(maxLines = 8) {
    let Exception = Java.use("java.lang.Exception");
    let stackTrace = Exception.$new().getStackTrace().toString().split(",");

    console.log("\nBacktrace:");
    for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
        console.log(stackTrace[i]);
    }
    console.log("\n");
  }

  function enumerateWebViews() {
    Java.choose("android.webkit.WebView", {
      onMatch: function(instance) {
        var id = instance.toString();
        if (seenWebViews[id]) return;  // Skip if already seen
        seenWebViews[id] = true;
        Java.scheduleOnMainThread(function() {
          console.log(`\n[*] Found WebView instance: ${id}`);
          try {
            internalCall = true; // Set flag before calling getSettings
            var settings = instance.getSettings();
            internalCall = false; // Reset flag after calling getSettings
            console.log(`\t[+] JavaScriptEnabled: ${settings.getJavaScriptEnabled()}`);
            console.log(`\t[+] AllowFileAccess: ${settings.getAllowFileAccess()}`);
            console.log(`\t[+] AllowFileAccessFromFileURLs: ${settings.getAllowFileAccessFromFileURLs()}`);
            console.log(`\t[+] AllowUniversalAccessFromFileURLs: ${settings.getAllowUniversalAccessFromFileURLs()}`);
            console.log(`\t[+] AllowContentAccess: ${settings.getAllowContentAccess()}`);
            console.log(`\t[+] MixedContentMode: ${settings.getMixedContentMode()}`);
            console.log(`\t[+] SafeBrowsingEnabled: ${settings.getSafeBrowsingEnabled()}`);
          } catch (err) {
            console.log(`\t[-] Error reading settings: ${err}`);
          }
        });
      },
      onComplete: function() {
        console.log("\n[*] Finished enumerating WebView instances!");
      }
    });
  }

  var WebView = Java.use("android.webkit.WebView");
  
  if (delayEnumerationUntilGetSettings) {
    var enumerationTriggered = false;
    WebView.getSettings.implementation = function() {
      if (internalCall) {
        return this.getSettings(); // Return immediately if it's an internal call
      }
      var settings = this.getSettings();
      var id = this.toString();
      console.log(`\n[*] WebView.getSettings() called on instance: ${id}`);
      printBacktrace();
      if (!enumerationTriggered) {
        enumerationTriggered = true;
        Java.scheduleOnMainThread(function() {
          console.log("\n[*] Triggering enumeration after getSettings() call...");
          enumerateWebViews();
        });
      }
      return settings;
    };
  } else {
    enumerateWebViews();
  }
});
