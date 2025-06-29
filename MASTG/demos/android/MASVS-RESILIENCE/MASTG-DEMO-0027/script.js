Java.perform(() => {

  // Function to print backtrace with a configurable number of lines (default: 5)
  function printBacktrace(maxLines = 8) {
      let Exception = Java.use("java.lang.Exception");
      let stackTrace = Exception.$new().getStackTrace().toString().split(",");

      console.log("\nBacktrace:");
      for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
          console.log(stackTrace[i]);
      }
  }
  
  // Hook KeyguardManager.isDeviceSecure()
  let KeyguardManager = Java.use("android.app.KeyguardManager");

  KeyguardManager["isDeviceSecure"].overload().implementation = function () {

      let result = this["isDeviceSecure"]();
      console.log(`\n\n[*] KeyguardManager.isDeviceSecure() called - RESULT: ${result}\n`);

      // Java stack trace
      printBacktrace();
      
      return result;
  };

  // Hook BiometricManager.canAuthenticate()
  const BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
  const Authenticators = Java.use("android.hardware.biometrics.BiometricManager$Authenticators");

  // Cache original implementation
  const originalCanAuth = BiometricManager.canAuthenticate.overload("int");

  // Map flag values to names
  const flagNames = {
    [Authenticators.BIOMETRIC_WEAK.value]: "BIOMETRIC_WEAK",
    [Authenticators.BIOMETRIC_STRONG.value]: "BIOMETRIC_STRONG",
    [Authenticators.DEVICE_CREDENTIAL.value]: "DEVICE_CREDENTIAL"
  };

  // Map result codes to messages
  const resultMessages = {
    [BiometricManager.BIOMETRIC_SUCCESS.value]: "BIOMETRIC_SUCCESS",
    [BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE.value]: "BIOMETRIC_ERROR_NO_HARDWARE",
    [BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE.value]: "BIOMETRIC_ERROR_HW_UNAVAILABLE",
    [BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED.value]: "BIOMETRIC_ERROR_NONE_ENROLLED"
  };

  originalCanAuth.implementation = function (authenticators) {
    // Build readable authenticators string
    const names = Object.keys(flagNames)
      .map(key => parseInt(key, 10))
      .filter(key => (authenticators & key) === key)
      .map(key => flagNames[key]);
    const readable = names.length ? names.join(" | ") : "NONE";

    // Call original
    const res = originalCanAuth.call(this, authenticators);

    // Lookup result message
    const msg = resultMessages[res] || `Unknown biometric status: ${res}`;

    console.log(`\n\n[*] BiometricManager.canAuthenticate called with: ${readable} (${authenticators}) - RESULT: ${msg} (${res})`);

    printBacktrace();

    return res;
  };
});
