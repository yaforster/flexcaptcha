package io.github.yaforster.flexcaptcha;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.SecureRandom;

public interface CipherHandler {

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
    byte[] encryptString(byte[] input, Cipher cipher);

    /**
     * Decrypts an encrypted string using a specified password and salt source
     * object. The decrypted string must contain the initialization vector as the
     * first 16 bytes as they will be extracted to be used in the decryption.
     *
     * @param input  the input byte array to be decrypted
     * @param cipher a preconfigured cipher object used for the decryption
     * @return the decrypted string
     */
    byte[] decryptString(byte[] input, Cipher cipher);

    /**
     * Gets the byte array of the salt source object
     *
     * @param saltSource object to be used as salt
     * @return byte array of the given object
     */
    default byte[] generateSaltBytes(Serializable saltSource) throws IOException {
        byte[] saltBytes;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out;
        out = new ObjectOutputStream(bos);
        out.writeObject(saltSource);
        out.flush();
        saltBytes = bos.toByteArray();
        return saltBytes;
    }

    /**
     * generates a new initialization vector as randomized 16 bytes and returns it
     * as {@link IvParameterSpec}
     *
     * @return randomized {@link IvParameterSpec}
     */
    default IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
