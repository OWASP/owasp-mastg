---
masvs_category: MASVS-RESILIENCE
platform: android
title: Device Binding
---

The goal of device binding is to impede an attacker who tries to both copy an app and its state from device A to device B and continue executing the app on device B. After device A has been determined trustworthy, it may have more privileges than device B. These differential privileges should not change when an app is copied from device A to device B.

Before we describe the usable identifiers, let's quickly discuss how they can be used for binding. There are three methods that allow device binding:

- Augmenting the credentials used for authentication with device identifiers. This make sense if the application needs to re-authenticate itself and/or the user frequently.

- Encrypting the data stored in the device with the key material which is strongly bound to the device can strengthen the device binding. The Android Keystore offers non-exportable private keys which we can use for this. When a malicious actor would extract such data from a device, it wouldn't be possible to decrypt the data, as the key is not accessible. Implementing this, takes the following steps:

    - Generate the key pair in the Android Keystore using `KeyGenParameterSpec` API.

      ```java
      //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
      keyPairGenerator.initialize(
              new KeyGenParameterSpec.Builder(
                      "key1",
                      KeyProperties.PURPOSE_DECRYPT)
                      .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                      .build());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
      ...

      // The key pair can also be obtained from the Android Keystore any time as follows:
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
      PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
      ```

    - Generating a secret key for AES-GCM:

      ```java
      //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
      KeyGenerator keyGenerator = KeyGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
      keyGenerator.init(
              new KeyGenParameterSpec.Builder("key2",
                      KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                      .build());
      SecretKey key = keyGenerator.generateKey();

      // The key can also be obtained from the Android Keystore any time as follows:
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      key = (SecretKey) keyStore.getKey("key2", null);
      ```

    - Encrypt the authentication data and other sensitive data stored by the application using a secret key through AES-GCM cipher and use device specific parameters such as Instance ID, etc. as associated data:

      ```java
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      final byte[] nonce = new byte[GCM_NONCE_LENGTH];
      random.nextBytes(nonce);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
      cipher.init(Cipher.ENCRYPT_MODE, key, spec);
      byte[] aad = "<deviceidentifierhere>".getBytes();;
      cipher.updateAAD(aad);
      cipher.init(Cipher.ENCRYPT_MODE, key);

      //use the cipher to encrypt the authentication data see 0x50e for more details.
      ```

    - Encrypt the secret key using the public key stored in Android Keystore and store the encrypted secret key in the private storage of the application.
    - Whenever authentication data such as access tokens or other sensitive data is required, decrypt the secret key using private key stored in Android Keystore and then use the decrypted secret key to decrypt the ciphertext.

- Use token-based device authentication (Instance ID) to make sure that the same instance of the app is used.
