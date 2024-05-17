    KeyPairGenerator keyPairGen1 = KeyPairGenerator.getInstance("RSA");
    keyPairGen1.initialize(1024); // BAD: Key size is less than 2048

    KeyPairGenerator keyPairGen4 = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp112r1"); // BAD: Key size is less than 256
    keyPairGen4.initialize(ecSpec);

    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(64); // BAD: Key size is less than 256