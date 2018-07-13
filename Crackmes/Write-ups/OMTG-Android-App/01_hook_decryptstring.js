Java.perform(function(){
  console.log("[*] script loaded");
  var clazz = Java.use("sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_KeyStore");

  clazz.decryptString.overload("java.lang.String").implementation = function (alias) {
    console.log("[*] decryptString called");
    console.log("[*] alias: " + alias);

    this.decryptString.overload("java.lang.String").call(this, alias);
  };
});
