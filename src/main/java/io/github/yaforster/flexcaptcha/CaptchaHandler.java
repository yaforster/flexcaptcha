package io.github.yaforster.flexcaptcha;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author Yannick Forster
 * This interface defines the basic functionality shared amongst all
 * Captcha handlers consisting of the adding of the handler reference to
 * the token itself as well as the validation method definition and
 * token creation implementation, the validation and
 * convertion of a salt object to byte arrays
 */
public interface CaptchaHandler {

    /**
     * Log4J Logger
     */
    Logger log = LogManager.getLogger(CaptchaHandler.class);

    /**
     * The algorithm used to hash
     */
    String ALGORITHM_NAME = "SHA-256";
    /**
     * The delimiter used to differentiate between the hashed portion of the token
     * and the self reference of the handler
     */
    String DELIMITER = "###";

    /**
     * Appends a given token with an encrypted self reference used for validation at
     * a later point. This is required because each handler implementation allows
     * for a customized validation and token generation logic, and validation of a
     * token can not be done reliably without knowing the implementation that
     * created it. This method encrypts the fully qualified name of the
     * implementation and appends it to the token. The {@link Validator} class can
     * be used to decrypt the token, instantiate the CaptchaHandler implementation
     * and run its validation.
     *
     * @param cipherHandler {@link DefaultCipherHandler} object used to handle the
     *                      encrypting of the self reference
     * @param saltSource    the salt source used for the encryption.
     * @param password      the password used to encrypt the implementation
     *                      reference
     * @return appended token string
     */
    default String makeSelfReference(DefaultCipherHandler cipherHandler, Serializable saltSource,
                                     String password) {
        byte[] ivBytes = cipherHandler.generateIV().getIV();
        Ciper cipher =
        byte[] encryptedBytes = cipherHandler.encryptString(this.getClass().getName().getBytes(), password, saltSource,
                ivBytes);
        String base64 = Base64.getEncoder().encodeToString(encryptedBytes);
        return DELIMITER + base64;
    }

    /**
     * Validates the answer to the captcha based on the token and the salt object.
     * Returns true if the answer is correct and the token authentic
     *
     * @param answer        the given solution to the captcha to be validated
     * @param cipherHandler {@link DefaultCipherHandler} object used to handle the
     *                      decryption of the self reference
     * @param token         the returned token originally created with the captcha
     * @param saltSource    the salt source originally used to salt the hashed
     *                      solution to create the token. Will be used again to
     *                      validate the answer
     * @param password      The password string used for decryption
     * @return boolean whether the captcha is valid
     */
    boolean validate(String answer, String token, DefaultCipherHandler cipherHandler, Serializable saltSource,
                     String password);

    /**
     * Creates the token based on the captcha solution and the object to be used for
     * salting
     *
     * @param sourceString captcha solution as string
     * @param saltSource   arbitrary object to be used to salt the solution hash for
     *                     added security and to allow for authenticating the given
     *                     answer
     * @return String of the token
     */
    default String makeToken(String sourceString, Serializable saltSource) {
        byte[] captchaTextBytes = sourceString.getBytes();
        byte[] saltObjectBytes = getSaltObjectBytes(saltSource);
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM_NAME);
            md.update(captchaTextBytes);
            md.update(saltObjectBytes);
            byte[] outputBytes = md.digest();
            return Base64.getEncoder().encodeToString(outputBytes);
        } catch (NoSuchAlgorithmException e) {
            log.error("Error creating the captcha token: " + e.getMessage());
            return null;
        }
    }

    /**
     * Converts the given object to a byte array
     *
     * @param saltSource object to be used as salt
     * @return byte array of the object
     */
    default byte[] getSaltObjectBytes(Serializable saltSource) {
        ByteArrayOutputStream baos;
        ObjectOutputStream oos;
        try {
            baos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(baos);
            oos.writeObject(saltSource);
            baos.close();
            oos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            log.error("Error converting the salt object source to byte array: " + e.getMessage());
            return null;
        }
    }

}