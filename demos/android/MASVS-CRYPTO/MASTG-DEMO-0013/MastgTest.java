public class Foo {
    void good() {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    void bad() {
        SecretKeySpec secretKeySpec = new SecretKeySpec("my secret here".getBytes(), "AES");
    }
}

public void setSecretKey(String secretKey) {
    String encryptionKey = "lakdsljkalkjlksdfkl";
    byte[] keyBytes = encryptionKey.getBytes();
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
}

public void setSecretKey(String secretKey) {

  SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");

}

public void setSecretKey(String secretKey) {

  byte[] bytes = secretKey.getBytes();

  SecretKey key = new SecretKeySpec(bytes, "AES");


}



