    KeyPairGenerator keyPairGen1 = KeyPairGenerator.getInstance("RSA");
    keyPairGen1.initialize(1024); // BAD: Key size is less than 2048

    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(64); // BAD: Key size is less than 256