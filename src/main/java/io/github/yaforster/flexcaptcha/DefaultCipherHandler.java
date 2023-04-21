package io.github.yaforster.flexcaptcha;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Example implementation.
 * Handles String encryption or decryption.
 *
 * @author Yannick Forster
 */
public class DefaultCipherHandler implements CipherHandler {

    /**
     * The encryption algorithm
     */
    static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    /**
     * The cipher algorithm
     */
    static final String CIPERALGORITHM = "AES/CBC/PKCS5Padding";
    /**
     * AES
     */
    static final String AES = "AES";
    /**
     * Log4J Logger
     */
    final Logger log = LogManager.getLogger(DefaultCipherHandler.class);

    /**
     * Encrypts a given String with a password and a salt source. To encrypt it, an
     * initialization vector is generated and used to encrypt the string. The
     * initialization vector is then put in front of the encrypted byte array for
     * transportation, so it can be used to decrypt the byte array after it (using
     * the same password and salt) at a later point.
     *
     * @param input  the input byte array to be encrypted
     * @param cipher a configured cipher object used for the encryption
     * @return the encrypted string
     */
    @Override
    public byte[] encryptString(byte[] input, Cipher cipher) {
        try {
            byte[] cipherBytes = cipher.doFinal(input);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(cipher.getIV());
            outputStream.write(cipherBytes);
            return outputStream.toByteArray();
        } catch (IOException e) {
            log.fatal("Fatal error producing byte array data of the salt source object: " + e.getLocalizedMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            log.fatal("Fatal error during token encryption: " + e.getLocalizedMessage());
        }
        return null;
    }

    /**
     * Decrypts an encrypted string using a specified password and salt source
     * object. The decrypted string must contain the initialization vector as the
     * first 16 bytes as they will be extracted to be used in the decryption.
     *
     * @param input  the input byte array to be decrypted
     * @param cipher a preconfigured cipher object used for the decryption
     * @return the decrypted string
     */
    @Override
    public byte[] decryptString(byte[] input, Cipher cipher) {
        try {
            byte[] cipherBytes = Arrays.copyOfRange(input, 16, input.length);
            return cipher.doFinal(cipherBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            log.fatal("Fatal error during token decryption: " + e.getLocalizedMessage());
        }
        return null;
    }

    /**
     * Generates and configures the {@link Cipher} object used for encryption and
     * decryption.
     *
     * @param password   the password used for encryption
     * @param saltSource a Serializable object used as salt
     * @param mode       specifies whether the cipher will encrypt or decrypt
     * @param ivBytes    the initialization vector
     * @return configured Cipher object
     */
    private Cipher getCipher(String password, Serializable saltSource, int mode, byte[] ivBytes)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPERALGORITHM);
        byte[] saltBytes = generateSaltBytes(saltSource);
        KeySpec ks = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
        SecretKey key = new SecretKeySpec(factory.generateSecret(ks).getEncoded(), AES);
        cipher.init(mode, key, iv);
        return cipher;
    }


}
