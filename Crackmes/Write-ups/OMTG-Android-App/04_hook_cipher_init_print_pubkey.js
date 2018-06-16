Java.perform(function(){
  console.log("[*] script loaded");

  var Cipher = Java.use("javax.crypto.Cipher");
  var RSAPublicKey = Java.use("java.security.interfaces.RSAPublicKey");
  var RSAKey = Java.use("java.security.interfaces.RSAKey");
  Cipher.init.overload('int', 'java.security.Key').implementation  = function(opmode, key){
      console.log("[*] Cipher.init called");
      console.log("[*] mode: " + opmode);

      if (opmode == 2){
        console.log("[*] decryption with private key!");      }

      else if (opmode == 1){
        console.log("[*] encryption with public key!");
        var pub_key = Java.cast(key, RSAPublicKey);
        var pub_key2 = Java.cast(key, RSAKey); // We cannot call getModulus() from RSAPublicKey, so we cast it to RSAKey
        console.log("[*] key: " + pub_key.toString());
        console.log("[*] key PublicExponent: " + pub_key.getPublicExponent());
        console.log("[*] key modulus: " + pub_key2.getModulus());
      }
      this.init.overload('int', 'java.security.Key').call(this, opmode, key);
  }
});
