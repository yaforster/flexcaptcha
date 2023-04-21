package io.github.yaforster.flexcaptcha.textbased.handling.impl;

import io.github.yaforster.flexcaptcha.DefaultCipherHandler;
import io.github.yaforster.flexcaptcha.textbased.TextCaptcha;
import io.github.yaforster.flexcaptcha.textbased.enums.Case;
import io.github.yaforster.flexcaptcha.textbased.handling.TextCaptchaHandler;
import io.github.yaforster.flexcaptcha.textbased.rendering.TextImageRenderer;
import io.github.yaforster.flexcaptcha.textbased.textgen.CaptchaTextGenerator;
import org.apache.commons.lang3.StringUtils;

import java.awt.image.BufferedImage;
import java.io.Serializable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Provides basic captcha handling regarding generation of a simplistic visual
 * representation of the text-based captcha string as well as hashing the token
 * and salt object
 *
 * @author Yannick Forster
 */
public class SimpleTextCaptchaHandler implements TextCaptchaHandler {

    /**
     * The image format
     */
    private static final String IMG_FORMAT = "JPEG";

    /**
     * Generates a TextCaptcha object containing the token and the images.
     */
    @Override
    public TextCaptcha generate(int length, DefaultCipherHandler cipherHandler, Serializable saltSource, String password,
                                CaptchaTextGenerator textgenerator, Case charCase, TextImageRenderer renderer, int height, int width, boolean addSelfReference) {
        checkInputs(length, textgenerator, renderer, height, width);
        String captchaText = textgenerator.generate(length, textgenerator.generate(length, charCase), charCase);
        return makeTextCaptcha(saltSource, cipherHandler, password, renderer, height, width, captchaText, addSelfReference);
    }

    /**
     * Validates whether the answer to the given captcha is correct. To do
     * this, the answer and the salt source are combined and checked against the
     * token
     */
    @Override
    public boolean validate(String answer, String token, DefaultCipherHandler cipherHandler, Serializable saltSource, String password) {
        return token.split(DELIMITER)[0].equals(makeToken(answer, saltSource));
    }

    /**
     * Generates the completed captcha object with a picture based on the specified
     * text directly, The implementation of creating the image is given by the
     * specified renderer. The salt source specifies an arbitrary object used to
     * salt the token. Use this method if you want a captcha knowing the solution
     * beforehand, as opposed to have it randomly generated.
     */
    public TextCaptcha toCaptcha(String captchaText, DefaultCipherHandler cipherHandler, Serializable saltSource, String password,
                                 TextImageRenderer renderer, int height, int width, boolean addSelfReference) {
        return makeTextCaptcha(saltSource, cipherHandler, password, renderer, height, width, captchaText, addSelfReference);
    }

    /**
     * Generates the completed captcha object with a picture based on the specified
     * text, heigth and width. The implementation of creating the image is given by
     * the specified renderer. The salt source specifies an arbitrary object used to
     * salt the token.
     *
     * @param saltSource  arbitrary object to be used to salt the solution hash for
     *                    added security and to allow for authenticating the given
     *                    answer
     * @param password    the password used to encrypt the implementation reference
     * @param renderer    Implementation of the ImageRenderer interface controlling
     *                    how the specified captcha is generated as an image.
     * @param height      pixel height of the captcha image
     * @param width       pixel width of the catpcha image
     * @param captchaText text the catpcha should display
     * @return {@link TextCaptcha} containing the finalized captcha
     */
    private TextCaptcha makeTextCaptcha(Serializable saltSource, DefaultCipherHandler cipherHandler, String password, TextImageRenderer renderer,
                                        int height, int width, String captchaText, boolean addSelfReference) {
        BufferedImage image = renderer.render(captchaText, height, width);
        TextCaptcha captcha = null;
        try {
            byte[] imgData = convertImageToByteArray(image, IMG_FORMAT);
            CompletableFuture<String> selfreference = CompletableFuture.completedFuture(StringUtils.EMPTY);
            if (addSelfReference) {
                selfreference = CompletableFuture.supplyAsync(() -> makeSelfReference(cipherHandler, saltSource, password));
            }
            CompletableFuture<String> token = CompletableFuture.supplyAsync(() -> makeToken(captchaText, saltSource));
            captcha = new TextCaptcha(imgData, token.get() + selfreference.get());
        } catch (InterruptedException e) {
            log.fatal("Thread interruption during captcha generation: " + e.getLocalizedMessage());

        } catch (ExecutionException e) {
            log.fatal("Fatal error during captcha generation: " + e.getLocalizedMessage());
        }
        return captcha;
    }

}
