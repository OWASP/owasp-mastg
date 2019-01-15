/*
 * Copyright (c) 2014-2015 Tozny LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Created by Isaac Potoczny-Jones on 11/12/14.
 */

package com.tozny.crypto.android;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.os.Build;
import android.os.Process;
import android.util.Base64;
import android.util.Log;

/**
 * Simple library for the "right" defaults for AES key generation, encryption,
 * and decryption using 128-bit AES, CBC, PKCS5 padding, and a random 16-byte IV
 * with SHA1PRNG. Integrity with HmacSHA256.
 */
public class AesCbcWithIntegrity {
    // If the PRNG fix would not succeed for some reason, we normally will throw an exception.
    // If ALLOW_BROKEN_PRNG is true, however, we will simply log instead.
    private static final boolean ALLOW_BROKEN_PRNG = false;

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CIPHER = "AES";
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int AES_KEY_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 16;
    private static final int PBE_ITERATION_COUNT = 10000;
    private static final int PBE_SALT_LENGTH_BITS = AES_KEY_LENGTH_BITS; // same size as key output
    private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA1";

    //Made BASE_64_FLAGS public as it's useful to know for compatibility.
    public static final int BASE64_FLAGS = Base64.NO_WRAP;
    //default for testing
    static final AtomicBoolean prngFixed = new AtomicBoolean(false);

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HMAC_KEY_LENGTH_BITS = 256;

    /**
     * Converts the given AES/HMAC keys into a base64 encoded string suitable for
     * storage. Sister function of keys.
     *
     * @param keys The combined aes and hmac keys
     * @return a base 64 encoded AES string & hmac key as base64(aesKey) : base64(hmacKey)
     */
    public static String keyString(SecretKeys keys) {
        return keys.toString();
    }

    /**
     * An aes key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     *
     * @param keysStr a base64 encoded AES key / hmac key as base64(aesKey) : base64(hmacKey).
     * @return an AES & HMAC key set suitable for other functions.
     */
    public static SecretKeys keys(String keysStr) throws InvalidKeyException {
        String[] keysArr = keysStr.split(":");

        if (keysArr.length != 2) {
            throw new IllegalArgumentException("Cannot parse aesKey:hmacKey");

        } else {
            byte[] confidentialityKey = Base64.decode(keysArr[0], BASE64_FLAGS);
            if (confidentialityKey.length != AES_KEY_LENGTH_BITS /8) {
                throw new InvalidKeyException("Base64 decoded key is not " + AES_KEY_LENGTH_BITS + " bytes");
            }
            byte[] integrityKey = Base64.decode(keysArr[1], BASE64_FLAGS);
            if (integrityKey.length != HMAC_KEY_LENGTH_BITS /8) {
                throw new InvalidKeyException("Base64 decoded key is not " + HMAC_KEY_LENGTH_BITS + " bytes");
            }

            return new SecretKeys(
                    new SecretKeySpec(confidentialityKey, 0, confidentialityKey.length, CIPHER),
                    new SecretKeySpec(integrityKey, HMAC_ALGORITHM));
        }
    }

    /**
     * A function that generates random AES & HMAC keys and prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKeys generateKey() throws GeneralSecurityException {
        fixPrng();
        KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
        // No need to provide a SecureRandom or set a seed since that will
        // happen automatically.
        keyGen.init(AES_KEY_LENGTH_BITS);
        SecretKey confidentialityKey = keyGen.generateKey();

        //Now make the HMAC key
        byte[] integrityKeyBytes = randomBytes(HMAC_KEY_LENGTH_BITS / 8);//to get bytes
        SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, HMAC_ALGORITHM);

        return new SecretKeys(confidentialityKey, integrityKey);
    }

    /**
     * A function that generates password-based AES & HMAC keys. It prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @param password The password to derive the keys from.
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKeys generateKeyFromPassword(String password, byte[] salt) throws GeneralSecurityException {
        fixPrng();
        //Get enough random bytes for both the AES key and the HMAC key:
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                PBE_ITERATION_COUNT, AES_KEY_LENGTH_BITS + HMAC_KEY_LENGTH_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory
                .getInstance(PBE_ALGORITHM);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        // Split the random bytes into two parts:
        byte[] confidentialityKeyBytes = copyOfRange(keyBytes, 0, AES_KEY_LENGTH_BITS /8);
        byte[] integrityKeyBytes = copyOfRange(keyBytes, AES_KEY_LENGTH_BITS /8, AES_KEY_LENGTH_BITS /8 + HMAC_KEY_LENGTH_BITS /8);

        //Generate the AES key
        SecretKey confidentialityKey = new SecretKeySpec(confidentialityKeyBytes, CIPHER);

        //Generate the HMAC key
        SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, HMAC_ALGORITHM);

        return new SecretKeys(confidentialityKey, integrityKey);
    }

    /**
     * A function that generates password-based AES & HMAC keys. See generateKeyFromPassword.
     * @param password The password to derive the AES/HMAC keys from
     * @param salt A string version of the salt; base64 encoded.
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException
     */
    public static SecretKeys generateKeyFromPassword(String password, String salt) throws GeneralSecurityException {
        return generateKeyFromPassword(password, Base64.decode(salt, BASE64_FLAGS));
    }

    /**
     * Generates a random salt.
     * @return The random salt suitable for generateKeyFromPassword.
     */
    public static byte[] generateSalt() throws GeneralSecurityException {
        return randomBytes(PBE_SALT_LENGTH_BITS);
    }

    /**
     * Converts the given salt into a base64 encoded string suitable for
     * storage.
     *
     * @param salt
     * @return a base 64 encoded salt string suitable to pass into generateKeyFromPassword.
     */
    public static String saltString(byte[] salt) {
        return Base64.encodeToString(salt, BASE64_FLAGS);
    }


    /**
     * Creates a random Initialization Vector (IV) of IV_LENGTH_BYTES.
     *
     * @return The byte array of this IV
     * @throws GeneralSecurityException if a suitable RNG is not available
     */
    public static byte[] generateIv() throws GeneralSecurityException {
        return randomBytes(IV_LENGTH_BYTES);
    }

    private static byte[] randomBytes(int length) throws GeneralSecurityException {
        fixPrng();
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] b = new byte[length];
        random.nextBytes(b);
        return b;
    }

    /*
     * -----------------------------------------------------------------
     * Encryption
     * -----------------------------------------------------------------
     */

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext The text that will be encrypted, which
     *                  will be serialized with UTF-8
     * @param secretKeys The AES & HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported in this system
     */
    public static CipherTextIvMac encrypt(String plaintext, SecretKeys secretKeys)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext, secretKeys, "UTF-8");
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext The bytes that will be encrypted
     * @param secretKeys The AES & HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the specified encoding is invalid
     */
    public static CipherTextIvMac encrypt(String plaintext, SecretKeys secretKeys, String encoding)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext.getBytes(encoding), secretKeys);
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext The text that will be encrypted
     * @param secretKeys The combined AES & HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    public static CipherTextIvMac encrypt(byte[] plaintext, SecretKeys secretKeys)
            throws GeneralSecurityException {
        byte[] iv = generateIv();
        Cipher aesCipherForEncryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
        aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKeys.getConfidentialityKey(), new IvParameterSpec(iv));

        /*
         * Now we get back the IV that will actually be used. Some Android
         * versions do funny stuff w/ the IV, so this is to work around bugs:
         */
        iv = aesCipherForEncryption.getIV();
        byte[] byteCipherText = aesCipherForEncryption.doFinal(plaintext);
        byte[] ivCipherConcat = CipherTextIvMac.ivCipherConcat(iv, byteCipherText);

        byte[] integrityMac = generateMac(ivCipherConcat, secretKeys.getIntegrityKey());
        return new CipherTextIvMac(byteCipherText, iv, integrityMac);
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     * Will only run once, and every subsequent call should return immediately.
     */
    private static void fixPrng() {
        if (!prngFixed.get()) {
            synchronized (PrngFixes.class) {
                if (!prngFixed.get()) {
                    PrngFixes.apply();
                    prngFixed.set(true);
                }
            }
        }
    }

    /*
     * -----------------------------------------------------------------
     * Decryption
     * -----------------------------------------------------------------
     */

    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The AES & HMAC keys
     * @param encoding The string encoding to use to decode the bytes after decryption
     * @return A string derived from the decrypted bytes (not base64 encoded)
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the encoding is unsupported
     */
    public static String decryptString(CipherTextIvMac civ, SecretKeys secretKeys, String encoding)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return new String(decrypt(civ, secretKeys), encoding);
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The AES & HMAC keys
     * @return A string derived from the decrypted bytes, which are interpreted
     *         as a UTF-8 String
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported
     */
    public static String decryptString(CipherTextIvMac civ, SecretKeys secretKeys)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return decryptString(civ, secretKeys, "UTF-8");
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ the cipher text, iv, and mac
     * @param secretKeys the AES & HMAC keys
     * @return The raw decrypted bytes
     * @throws GeneralSecurityException if MACs don't match or AES is not implemented
     */
    public static byte[] decrypt(CipherTextIvMac civ, SecretKeys secretKeys)
            throws GeneralSecurityException {

        byte[] ivCipherConcat = CipherTextIvMac.ivCipherConcat(civ.getIv(), civ.getCipherText());
        byte[] computedMac = generateMac(ivCipherConcat, secretKeys.getIntegrityKey());
        if (constantTimeEq(computedMac, civ.getMac())) {
            Cipher aesCipherForDecryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKeys.getConfidentialityKey(),
                    new IvParameterSpec(civ.getIv()));
            return aesCipherForDecryption.doFinal(civ.getCipherText());
        } else {
            throw new GeneralSecurityException("MAC stored in civ does not match computed MAC.");
        }
    }

    /*
     * -----------------------------------------------------------------
     * Helper Code
     * -----------------------------------------------------------------
     */

    /**
     * Generate the mac based on HMAC_ALGORITHM
     * @param integrityKey The key used for hmac
     * @param byteCipherText the cipher text
     * @return A byte array of the HMAC for the given key & ciphertext
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] generateMac(byte[] byteCipherText, SecretKey integrityKey) throws NoSuchAlgorithmException, InvalidKeyException {
        //Now compute the mac for later integrity checking
        Mac sha256_HMAC = Mac.getInstance(HMAC_ALGORITHM);
        sha256_HMAC.init(integrityKey);
        return sha256_HMAC.doFinal(byteCipherText);
    }
    /**
     * Holder class that has both the secret AES key for encryption (confidentiality)
     * and the secret HMAC key for integrity.
     */

    public static class SecretKeys {
        private SecretKey confidentialityKey;
        private SecretKey integrityKey;

        /**
         * Construct the secret keys container.
         * @param confidentialityKeyIn The AES key
         * @param integrityKeyIn the HMAC key
         */
        public SecretKeys(SecretKey confidentialityKeyIn, SecretKey integrityKeyIn) {
            setConfidentialityKey(confidentialityKeyIn);
            setIntegrityKey(integrityKeyIn);
        }

        public SecretKey getConfidentialityKey() {
            return confidentialityKey;
        }

        public void setConfidentialityKey(SecretKey confidentialityKey) {
            this.confidentialityKey = confidentialityKey;
        }

        public SecretKey getIntegrityKey() {
            return integrityKey;
        }

        public void setIntegrityKey(SecretKey integrityKey) {
            this.integrityKey = integrityKey;
        }

        /**
         * Encodes the two keys as a string
         * @return base64(confidentialityKey):base64(integrityKey)
         */
        @Override
        public String toString () {
            return Base64.encodeToString(getConfidentialityKey().getEncoded(), BASE64_FLAGS)
                    + ":" + Base64.encodeToString(getIntegrityKey().getEncoded(), BASE64_FLAGS);
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + confidentialityKey.hashCode();
            result = prime * result + integrityKey.hashCode();
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            SecretKeys other = (SecretKeys) obj;
            if (!integrityKey.equals(other.integrityKey))
                return false;
            if (!confidentialityKey.equals(other.confidentialityKey))
                return false;
            return true;
        }
    }


    /**
     * Simple constant-time equality of two byte arrays. Used for security to avoid timing attacks.
     * @param a
     * @param b
     * @return true iff the arrays are exactly equal.
     */
    public static boolean constantTimeEq(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Holder class that allows us to bundle ciphertext and IV together.
     */
    public static class CipherTextIvMac {
        private final byte[] cipherText;
        private final byte[] iv;
        private final byte[] mac;

        public byte[] getCipherText() {
            return cipherText;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getMac() {
            return mac;
        }

        /**
         * Construct a new bundle of ciphertext and IV.
         * @param c The ciphertext
         * @param i The IV
         * @param h The mac
         */
        public CipherTextIvMac(byte[] c, byte[] i, byte[] h) {
            cipherText = new byte[c.length];
            System.arraycopy(c, 0, cipherText, 0, c.length);
            iv = new byte[i.length];
            System.arraycopy(i, 0, iv, 0, i.length);
            mac = new byte[h.length];
            System.arraycopy(h, 0, mac, 0, h.length);
        }

        /**
         * Constructs a new bundle of ciphertext and IV from a string of the
         * format <code>base64(iv):base64(ciphertext)</code>.
         *
         * @param base64IvAndCiphertext A string of the format
         *            <code>iv:ciphertext</code> The IV and ciphertext must each
         *            be base64-encoded.
         */
        public CipherTextIvMac(String base64IvAndCiphertext) {
            String[] civArray = base64IvAndCiphertext.split(":");
            if (civArray.length != 3) {
                throw new IllegalArgumentException("Cannot parse iv:ciphertext:mac");
            } else {
                iv = Base64.decode(civArray[0], BASE64_FLAGS);
                mac = Base64.decode(civArray[1], BASE64_FLAGS);
                cipherText = Base64.decode(civArray[2], BASE64_FLAGS);
            }
        }

        /**
         * Concatinate the IV to the cipherText using array copy.
         * This is used e.g. before computing mac.
         * @param iv The IV to prepend
         * @param cipherText the cipherText to append
         * @return iv:cipherText, a new byte array.
         */
        public static byte[] ivCipherConcat(byte[] iv, byte[] cipherText) {
            byte[] combined = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
            return combined;
        }

        /**
         * Encodes this ciphertext, IV, mac as a string.
         *
         * @return base64(iv) : base64(mac) : base64(ciphertext).
         * The iv and mac go first because they're fixed length.
         */
        @Override
        public String toString() {
            String ivString = Base64.encodeToString(iv, BASE64_FLAGS);
            String cipherTextString = Base64.encodeToString(cipherText, BASE64_FLAGS);
            String macString = Base64.encodeToString(mac, BASE64_FLAGS);
            return String.format(ivString + ":" + macString + ":" + cipherTextString);
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(cipherText);
            result = prime * result + Arrays.hashCode(iv);
            result = prime * result + Arrays.hashCode(mac);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            CipherTextIvMac other = (CipherTextIvMac) obj;
            if (!Arrays.equals(cipherText, other.cipherText))
                return false;
            if (!Arrays.equals(iv, other.iv))
                return false;
            if (!Arrays.equals(mac, other.mac))
                return false;
            return true;
        }
    }

    /**
     * Copy the elements from the start to the end
     *
     * @param from  the source
     * @param start the start index to copy
     * @param end   the end index to finish
     * @return the new buffer
     */
    private static byte[] copyOfRange(byte[] from, int start, int end) {
        int length = end - start;
        byte[] result = new byte[length];
        System.arraycopy(from, start, result, 0, length);
        return result;
    }

    /**
     * Fixes for the RNG as per
     * http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
     *
     * This software is provided 'as-is', without any express or implied
     * warranty. In no event will Google be held liable for any damages arising
     * from the use of this software.
     *
     * Permission is granted to anyone to use this software for any purpose,
     * including commercial applications, and to alter it and redistribute it
     * freely, as long as the origin is not misrepresented.
     *
     * Fixes for the output of the default PRNG having low entropy.
     *
     * The fixes need to be applied via {@link #apply()} before any use of Java
     * Cryptography Architecture primitives. A good place to invoke them is in
     * the application's {@code onCreate}.
     */
    public static final class PrngFixes {

        private static final int VERSION_CODE_JELLY_BEAN = 16;
        private static final int VERSION_CODE_JELLY_BEAN_MR2 = 18;
        private static final byte[] BUILD_FINGERPRINT_AND_DEVICE_SERIAL = getBuildFingerprintAndDeviceSerial();

        /** Hidden constructor to prevent instantiation. */
        private PrngFixes() {
        }

        /**
         * Applies all fixes.
         *
         * @throws SecurityException if a fix is needed but could not be
         *             applied.
         */
        public static void apply() {
            applyOpenSSLFix();
            installLinuxPRNGSecureRandom();
        }

        /**
         * Applies the fix for OpenSSL PRNG having low entropy. Does nothing if
         * the fix is not needed.
         *
         * @throws SecurityException if the fix is needed but could not be
         *             applied.
         */
        private static void applyOpenSSLFix() throws SecurityException {
            if ((Build.VERSION.SDK_INT < VERSION_CODE_JELLY_BEAN)
                    || (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2)) {
                // No need to apply the fix
                return;
            }

            try {
                // Mix in the device- and invocation-specific seed.
                Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                        .getMethod("RAND_seed", byte[].class).invoke(null, generateSeed());

                // Mix output of Linux PRNG into OpenSSL's PRNG
                int bytesRead = (Integer) Class
                        .forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                        .getMethod("RAND_load_file", String.class, long.class)
                        .invoke(null, "/dev/urandom", 1024);
                if (bytesRead != 1024) {
                    throw new IOException("Unexpected number of bytes read from Linux PRNG: "
                            + bytesRead);
                }
            } catch (Exception e) {
                if (ALLOW_BROKEN_PRNG) {
                    Log.w(PrngFixes.class.getSimpleName(), "Failed to seed OpenSSL PRNG", e);
                } else {
                    throw new SecurityException("Failed to seed OpenSSL PRNG", e);
                }
            }
        }

        /**
         * Installs a Linux PRNG-backed {@code SecureRandom} implementation as
         * the default. Does nothing if the implementation is already the
         * default or if there is not need to install the implementation.
         *
         * @throws SecurityException if the fix is needed but could not be
         *             applied.
         */
        private static void installLinuxPRNGSecureRandom() throws SecurityException {
            if (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2) {
                // No need to apply the fix
                return;
            }

            // Install a Linux PRNG-based SecureRandom implementation as the
            // default, if not yet installed.
            Provider[] secureRandomProviders = Security.getProviders("SecureRandom.SHA1PRNG");

            // Insert and check the provider atomically.
            // The official Android Java libraries use synchronized methods for
            // insertProviderAt, etc., so synchronizing on the class should
            // make things more stable, and prevent race conditions with other
            // versions of this code.
            synchronized (java.security.Security.class) {
                if ((secureRandomProviders == null)
                        || (secureRandomProviders.length < 1)
                        || (!secureRandomProviders[0].getClass().getSimpleName().equals("LinuxPRNGSecureRandomProvider"))) {
                    Security.insertProviderAt(new LinuxPRNGSecureRandomProvider(), 1);
                }

                // Assert that new SecureRandom() and
                // SecureRandom.getInstance("SHA1PRNG") return a SecureRandom backed
                // by the Linux PRNG-based SecureRandom implementation.
                SecureRandom rng1 = new SecureRandom();
                if (!rng1.getProvider().getClass().getSimpleName().equals("LinuxPRNGSecureRandomProvider")) {
                    if (ALLOW_BROKEN_PRNG) {
                        Log.w(PrngFixes.class.getSimpleName(),
                                "new SecureRandom() backed by wrong Provider: " + rng1.getProvider().getClass());
                        return;
                    } else {
                        throw new SecurityException("new SecureRandom() backed by wrong Provider: "
                                + rng1.getProvider().getClass());
                    }
                }

                SecureRandom rng2 = null;
                try {
                    rng2 = SecureRandom.getInstance("SHA1PRNG");
                } catch (NoSuchAlgorithmException e) {
                    if (ALLOW_BROKEN_PRNG) {
                        Log.w(PrngFixes.class.getSimpleName(), "SHA1PRNG not available", e);
                        return;
                    } else {
                        new SecurityException("SHA1PRNG not available", e);
                    }
                }
                if (!rng2.getProvider().getClass().getSimpleName().equals("LinuxPRNGSecureRandomProvider")) {
                    if (ALLOW_BROKEN_PRNG) {
                        Log.w(PrngFixes.class.getSimpleName(),
                                "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong" + " Provider: "
                                        + rng2.getProvider().getClass());
                        return;
                    } else {
                        throw new SecurityException(
                                "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong" + " Provider: "
                                        + rng2.getProvider().getClass());
                    }
                }
            }
        }

        /**
         * {@code Provider} of {@code SecureRandom} engines which pass through
         * all requests to the Linux PRNG.
         */
        private static class LinuxPRNGSecureRandomProvider extends Provider {

            public LinuxPRNGSecureRandomProvider() {
                super("LinuxPRNG", 1.0, "A Linux-specific random number provider that uses"
                        + " /dev/urandom");
                // Although /dev/urandom is not a SHA-1 PRNG, some apps
                // explicitly request a SHA1PRNG SecureRandom and we thus need
                // to prevent them from getting the default implementation whose
                // output may have low entropy.
                put("SecureRandom.SHA1PRNG", LinuxPRNGSecureRandom.class.getName());
                put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
            }
        }

        /**
         * {@link SecureRandomSpi} which passes all requests to the Linux PRNG (
         * {@code /dev/urandom}).
         */
        public static class LinuxPRNGSecureRandom extends SecureRandomSpi {

            /*
             * IMPLEMENTATION NOTE: Requests to generate bytes and to mix in a
             * seed are passed through to the Linux PRNG (/dev/urandom).
             * Instances of this class seed themselves by mixing in the current
             * time, PID, UID, build fingerprint, and hardware serial number
             * (where available) into Linux PRNG.
             *
             * Concurrency: Read requests to the underlying Linux PRNG are
             * serialized (on sLock) to ensure that multiple threads do not get
             * duplicated PRNG output.
             */

            private static final File URANDOM_FILE = new File("/dev/urandom");

            private static final Object sLock = new Object();

            /**
             * Input stream for reading from Linux PRNG or {@code null} if not
             * yet opened.
             *
             * @GuardedBy("sLock")
             */
            private static DataInputStream sUrandomIn;

            /**
             * Output stream for writing to Linux PRNG or {@code null} if not
             * yet opened.
             *
             * @GuardedBy("sLock")
             */
            private static OutputStream sUrandomOut;

            /**
             * Whether this engine instance has been seeded. This is needed
             * because each instance needs to seed itself if the client does not
             * explicitly seed it.
             */
            private boolean mSeeded;

            @Override
            protected void engineSetSeed(byte[] bytes) {
                try {
                    OutputStream out;
                    synchronized (sLock) {
                        out = getUrandomOutputStream();
                    }
                    out.write(bytes);
                    out.flush();
                } catch (IOException e) {
                    // On a small fraction of devices /dev/urandom is not
                    // writable Log and ignore.
                    Log.w(PrngFixes.class.getSimpleName(), "Failed to mix seed into "
                            + URANDOM_FILE);
                } finally {
                    mSeeded = true;
                }
            }

            @Override
            protected void engineNextBytes(byte[] bytes) {
                if (!mSeeded) {
                    // Mix in the device- and invocation-specific seed.
                    engineSetSeed(generateSeed());
                }

                try {
                    DataInputStream in;
                    synchronized (sLock) {
                        in = getUrandomInputStream();
                    }
                    synchronized (in) {
                        in.readFully(bytes);
                    }
                } catch (IOException e) {
                    throw new SecurityException("Failed to read from " + URANDOM_FILE, e);
                }
            }

            @Override
            protected byte[] engineGenerateSeed(int size) {
                byte[] seed = new byte[size];
                engineNextBytes(seed);
                return seed;
            }

            private DataInputStream getUrandomInputStream() {
                synchronized (sLock) {
                    if (sUrandomIn == null) {
                        // NOTE: Consider inserting a BufferedInputStream
                        // between DataInputStream and FileInputStream if you need
                        // higher PRNG output performance and can live with future PRNG
                        // output being pulled into this process prematurely.
                        try {
                            sUrandomIn = new DataInputStream(new FileInputStream(URANDOM_FILE));
                        } catch (IOException e) {
                            throw new SecurityException("Failed to open " + URANDOM_FILE
                                    + " for reading", e);
                        }
                    }
                    return sUrandomIn;
                }
            }

            private OutputStream getUrandomOutputStream() throws IOException {
                synchronized (sLock) {
                    if (sUrandomOut == null) {
                        sUrandomOut = new FileOutputStream(URANDOM_FILE);
                    }
                    return sUrandomOut;
                }
            }
        }

        /**
         * Generates a device- and invocation-specific seed to be mixed into the
         * Linux PRNG.
         */
        private static byte[] generateSeed() {
            try {
                ByteArrayOutputStream seedBuffer = new ByteArrayOutputStream();
                DataOutputStream seedBufferOut = new DataOutputStream(seedBuffer);
                seedBufferOut.writeLong(System.currentTimeMillis());
                seedBufferOut.writeLong(System.nanoTime());
                seedBufferOut.writeInt(Process.myPid());
                seedBufferOut.writeInt(Process.myUid());
                seedBufferOut.write(BUILD_FINGERPRINT_AND_DEVICE_SERIAL);
                seedBufferOut.close();
                return seedBuffer.toByteArray();
            } catch (IOException e) {
                throw new SecurityException("Failed to generate seed", e);
            }
        }

        /**
         * Gets the hardware serial number of this device.
         *
         * @return serial number or {@code null} if not available.
         */
        private static String getDeviceSerialNumber() {
            // We're using the Reflection API because Build.SERIAL is only
            // available since API Level 9 (Gingerbread, Android 2.3).
            try {
                return (String) Build.class.getField("SERIAL").get(null);
            } catch (Exception ignored) {
                return null;
            }
        }

        private static byte[] getBuildFingerprintAndDeviceSerial() {
            StringBuilder result = new StringBuilder();
            String fingerprint = Build.FINGERPRINT;
            if (fingerprint != null) {
                result.append(fingerprint);
            }
            String serial = getDeviceSerialNumber();
            if (serial != null) {
                result.append(serial);
            }
            try {
                return result.toString().getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 encoding not supported");
            }
        }
    }
}