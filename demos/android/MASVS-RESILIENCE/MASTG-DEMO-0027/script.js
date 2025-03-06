Java.perform(() => {
  let KeyguardManager = Java.use("android.app.KeyguardManager");
  KeyguardManager["isDeviceSecure"].overload().implementation = function () {
      console.log(`KeyguardManager.isDeviceSecure() is called`);
      let result = this["isDeviceSecure"]();
      return result;
  };
});
