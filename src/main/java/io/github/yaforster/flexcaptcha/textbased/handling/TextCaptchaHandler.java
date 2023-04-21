package io.github.yaforster.flexcaptcha.textbased.handling;

import io.github.yaforster.flexcaptcha.CaptchaHandler;
import io.github.yaforster.flexcaptcha.DefaultCipherHandler;
import io.github.yaforster.flexcaptcha.textbased.TextCaptcha;
import io.github.yaforster.flexcaptcha.textbased.enums.Case;
import io.github.yaforster.flexcaptcha.textbased.rendering.TextImageRenderer;
import io.github.yaforster.flexcaptcha.textbased.textgen.CaptchaTextGenerator;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

/**
 * Interface for the various ways in which a captcha could potentially be
 * created.
 *
 * @author Yannick Forster
 */
public interface TextCaptchaHandler extends CaptchaHandler {

    /**
     * Generates a captcha of a given character length and salts the hashed solution
     * with the given object for checking authenticity during verification. Uses the
     * given String as a source of all possible characters from which the captcha
     * string is to be generated with mixed case.
     * <p>
     *
     * @param length        specifies the length
     * @param cipherHandler {@link DefaultCipherHandler} implementation for encryption and
     *                      decryption
     * @param saltSource    Object used during creation of the captcha token to
     *                      ensure authenticity
     * @param password      the password for encryption
     * @param textgenerator a {@link CaptchaTextGenerator} implementation
     * @param renderer      a {@link TextImageRenderer} implementation handling the
     *                      visualization of the text as image
     * @param height        the pixel height of the captcha image
     * @param width         the pixel width of the captcha image
     * @return Captcha object containing the image data of the visual captcha and
     * the token containing the hashed and salted solution
     */
    default TextCaptcha generate(int length, DefaultCipherHandler cipherHandler, Serializable saltSource,
                                 String password, CaptchaTextGenerator textgenerator, TextImageRenderer renderer, int height, int width, boolean addSelfReference) {
        return generate(length, cipherHandler, saltSource, password, textgenerator, Case.MIXEDCASE, renderer, height,
                width, addSelfReference);
    }

    /**
     * Generates a captcha of a given character length and salts the hashed solution
     * with the given object for checking authenticity during verification. Uses the
     * given String as a source of all possible characters from which the captcha
     * string is to be generated with the specified case.
     *
     * @param length        specifies the length
     * @param cipherHandler {@link DefaultCipherHandler} implementation for encryption and
     *                      decryption
     * @param saltSource    Object used during creation of the captcha token to
     *                      ensure authenticity
     * @param password      the password for encryption
     * @param textgenerator a {@link CaptchaTextGenerator} implementation
     * @param renderer      a {@link TextImageRenderer} implementation handling the
     *                      visualization of the text as image
     * @param charCase      a {@link Case} enum defining what letter case is allowed
     *                      in the generation
     * @param height        the pixel height of the captcha image
     * @param width         the pixel width of the captcha image
     * @return Captcha object containing the image data of the visual captcha and
     * the token containing the hashed and salted solution
     */
    TextCaptcha generate(int length, DefaultCipherHandler cipherHandler, Serializable saltSource, String password,
                         CaptchaTextGenerator textgenerator, Case charCase, TextImageRenderer renderer, int height, int width, boolean addSelfReference);

    /**
     * Generates a captcha from a given string and salt object
     *
     * @param captchaText   predefined string from which the image and the token are
     *                      generated
     * @param cipherHandler {@link DefaultCipherHandler} implementation for encryption and
     *                      decryption
     * @param saltSource    Object used during creation of the captcha token to
     *                      ensure authenticity
     * @param password      the password used to encrypt the implementation
     *                      reference
     * @param renderer      a {@link TextImageRenderer} implementation handling the
     *                      visualization of the text as image
     * @param height        the pixel height of the captcha image
     * @param width         the pixel width of the captcha image
     * @return Captcha object containing the image data of the visual captcha and
     * the token containing the hashed and salted solution
     */
    TextCaptcha toCaptcha(String captchaText, DefaultCipherHandler cipherHandler, Serializable saltSource,
                          String password, TextImageRenderer renderer, int height, int width, boolean addSelfReference);

    /**
     * Converts a buffered image to a byte array
     *
     * @param image     Image of the captcha
     * @param imgFormat the image format in which the raw image data is written
     * @return byte array of the image
     */
    default byte[] convertImageToByteArray(BufferedImage image, String imgFormat) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ImageIO.write(image, imgFormat, bos);
            return bos.toByteArray();
        } catch (final IOException e) {
            log.error("Error converting the BufferedImage to byte array: " + e.getMessage());
            return null;
        }
    }

    /**
     * @param length        the length of the Captcha
     * @param textgenerator the given {@link CaptchaTextGenerator} to generate the captcha text
     * @param renderer      the given {@link TextImageRenderer} to generate the captcha image
     * @param height        the height of the image to be generated by the renderer
     * @param width         the width of the image to be generated by the renderer
     */
    default void checkInputs(int length, CaptchaTextGenerator textgenerator, TextImageRenderer renderer, int height, int width) {
        if (renderer == null) {
            throw new IllegalArgumentException("The renderer cannot be null.");
        }
        if (textgenerator == null) {
            throw new IllegalArgumentException("The text generator cannot be null.");
        }
        if (length <= 0) {
            throw new IllegalArgumentException("The length must be an integer larger than 0.");
        }
        if (height <= 2) {
            throw new IllegalArgumentException("The height must be an integer larger than 2.");
        }
        if (width <= 0) {
            throw new IllegalArgumentException("The width must be an integer larger than 0.");
        }
    }

}
