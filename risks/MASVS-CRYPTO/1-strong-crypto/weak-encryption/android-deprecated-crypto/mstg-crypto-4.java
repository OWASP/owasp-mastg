import android.security.keystore.KeyGenParameterSpec.Builder;
import javax.crypto.Cipher;


public class TestCryptoAndroid {
    
    private void vuln_generateKey1() {
        // Vulnerable 
        //[...]
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        // ruleid: MSTG-CRYPTO-4
        keyGenerator.initialize(new KeyGenParameterSpec.Builder("key2", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                 .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                 .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                 .build());
        SecretKey key = keyGenerator.generateKey();
    }

        private void vuln_generateKey2() {
        // Vulnerable 
        //[...]
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        // ruleid: MSTG-CRYPTO-4
        keyGenerator.initialize(new KeyGenParameterSpec.Builder("key2", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                 .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                 .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                 .build());
        SecretKey key = keyGenerator.generateKey();
    }



    private void good_generateKey() {
        // Good 
        //[...]
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,ANDROID_KEY_STORE);
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                        keyName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();
        keyGenerator.init(keyGenParameterSpec);
        secretKey = keyGenerator.generateKey();
    }
    

        
    private void vuln_generateKey3() {
        // Vulnerable 
        //[...]
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,ANDROID_KEY_STORE);
        // ruleid: MSTG-CRYPTO-4
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                        keyName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .build();
        keyGenerator.init(keyGenParameterSpec);
        secretKey = keyGenerator.generateKey();
    }
    
    
    
        private void vuln_generateKey4() {
        // Vulnerable 
        //[...]
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,ANDROID_KEY_STORE);
        // ruleid: MSTG-CRYPTO-4
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                        keyName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .build();
        keyGenerator.init(keyGenParameterSpec);
        secretKey = keyGenerator.generateKey();
    }
    
    
    
    public String vuln_encrypt(String toEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Vulnerable 
        //[...]
        // ruleid: MSTG-CRYPTO-4
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //[...]
    }
    
    
    
    public String good_encrypt(String toEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Good 
        //[...]
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //[...]
    }    
    
    
    
    public static String vuln_decrypt(String key, String data) {
	// Vulnerable 
        //[...]
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        // ruleid: MSTG-CRYPTO-4
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        Key secretKey = keyFactory.generateSecret(dks);
	//[...]
    }    
    
    
}
