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
      console.log(`\n[*] KeyguardManager.isDeviceSecure() called\n`);

      // Java stack trace
      printBacktrace();

      let result = this["isDeviceSecure"]();
      console.log(`Result: ${result}`);
      return result;
  };

  // Hook BiometricManager.canAuthenticate()
  let BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");

  BiometricManager["canAuthenticate"].overload("int").implementation = function (authenticators) {

      let result = this["canAuthenticate"](authenticators);
      let statusMessage;

      // Mapping the authentication result to a readable message
      switch (result) {
          case BiometricManager.BIOMETRIC_SUCCESS.value:
              statusMessage = "BIOMETRIC_SUCCESS - Strong biometric authentication is available.";
              break;
          case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE.value:
              statusMessage = "BIOMETRIC_ERROR_NO_HARDWARE - No biometric hardware available.";
              break;
          case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE.value:
              statusMessage = "BIOMETRIC_ERROR_HW_UNAVAILABLE - Biometric hardware is currently unavailable.";
              break;
          case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED.value:
              statusMessage = "BIOMETRIC_ERROR_NONE_ENROLLED - No biometrics enrolled.";
              break;
          default:
              statusMessage = `Unknown biometric status: ${result}`;
              break;
      }

      console.log(`\n[*] BiometricManager.canAuthenticate(${authenticators}) called with ${statusMessage}\n`);


      // Java stack trace
      printBacktrace();
      

      return result;
  };
});
