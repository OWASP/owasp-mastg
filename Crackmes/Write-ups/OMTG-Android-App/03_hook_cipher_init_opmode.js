Java.perform(function(){
  console.log("[*] script loaded");

  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.init.overload('int', 'java.security.Key').implementation  = function(opmode, key){
      console.log("[*] Cipher.init called");
      console.log("[*] mode: " + opmode);

      if (opmode == 2){
        console.log("[*] decryption with private key!");      }

      else if (opmode == 1){
        console.log("[*] encryption with public key!");
      }
      this.init.overload('int', 'java.security.Key').call(this, opmode, key);
  }
});
