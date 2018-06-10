Java.perform(function(){

  function bytesToHex(bytes) {
      for (var hex = [], i = 0; i < bytes.length; i++) { hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
          hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
          hex.push(" ");
      }
      return hex.join("");
  }

  console.log("[*] script loaded");
  var clazz = Java.use("sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_KeyStore");

  clazz.decryptString.overload("java.lang.String").implementation = function (alias) {
    console.log("[*] decryptString called");
    console.log("[*] alias: " + alias);

    this.decryptString.overload("java.lang.String").call(this, alias);
  };

  var RSAPublicKey = Java.use("java.security.interfaces.RSAPublicKey");
  var RSAKey = Java.use("java.security.interfaces.RSAKey");
  var RSAPrivateKey = Java.use("java.security.interfaces.RSAPrivateKey");

  var OpenSSLRSAPrivateKey = Java.use("com.android.org.conscrypt.OpenSSLRSAPrivateKey");
  var OpenSSLKey = Java.use("com.android.org.conscrypt.OpenSSLKey");

  OpenSSLKey.isEngineBased.overload().implementation  = function(){
    console.log("[*] OpenSSLKey.isEngineBased called");
    return false;
  }

  var NativeCrypto = Java.use("com.android.org.conscrypt.NativeCrypto");

  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.init.overload('int', 'java.security.Key').implementation  = function(opmode, key){
      console.log("[*] Cipher.init called");
      console.log("[*] mode: " + opmode);

      if (opmode == 2){
        console.log("[*] decryption with private key!");
        //var priv_key = Java.cast(key, RSAPrivateKey);
        var priv_key = Java.cast(key, OpenSSLRSAPrivateKey);
        //console.log("[*] key PrivateExponent: " + priv_key.getPrivateExponent());
        //console.log("[*] Private Key encoded: " + priv_key.getEncoded());
        console.log("[*] Private Key encoded: " + bytesToHex(priv_key.getEncoded()));
        try {
          console.log("[*] key PrivateExponent: " + priv_key.getPrivateExponent());
        }
        catch (err){
          console.log("[*] Exception in priv_key.getPrivateExponent(): " + err.message);
        }

        //console.log("[*] key format: " + priv_key.getFormat());
      }

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
