Java.perform(function(){
  console.log("[*] script loaded");

  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.init.overload('int', 'java.security.Key').implementation  = function(opmode, key){
      console.log("[*] Cipher.init called");
      this.init.overload('int', 'java.security.Key').call(this, opmode, key);
  }
});
