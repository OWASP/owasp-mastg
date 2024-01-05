public class A{
    // ruleid: MSTG-CRYPTO-1
    byte[] key = new byte[]{2,7,2,9};
    byte[] iv = new byte[]{12};
    
    private byte[] aes(byte[] data, int mode){
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(mode, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
}
public class B{
    // ruleid: MSTG-CRYPTO-1
    String key = "SuperPassword123!";
    byte[] iv = new byte[]{12};
    
    private byte[] aes(byte[] data, int mode){
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(mode, new SecretKeySpec(this.key.getBytes(), "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
}
public class C{
    String key;
    byte[] iv = new byte[]{12};
    
    private byte[] aes(byte[] data, int mode){
        // ruleid: MSTG-CRYPTO-1
        key = getString(R.string.key);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(mode, new SecretKeySpec(key.toByteArray(), "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
}
