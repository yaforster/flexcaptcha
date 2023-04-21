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
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Provides basic captcha handling regarding the generation of a simplistic visual
 * representation of the text-based captcha string as well as encrypting the
 * token and salt object
 *
 * @author Yannick Forster
 */
public class SecureTextCaptchaHandler implements TextCaptchaHandler {

    /**
     * The image format
     */
    private static final String IMG_FORMAT = "JPEG";

    @Override
    public TextCaptcha generate(int length, DefaultCipherHandler cipherHandler, Serializable saltSource, String password,
                                CaptchaTextGenerator textGenerator, Case charCase, TextImageRenderer renderer, int height, int width, boolean addSelfReference) {
        checkInputs(length, textGenerator, renderer, height, width);
        String captchaText = textGenerator.generate(length, textGenerator.generate(length, charCase), charCase);
        return toCaptcha(captchaText, cipherHandler, saltSource, password, renderer, height, width, addSelfReference);
    }

    public TextCaptcha toCaptcha(String captchaText, DefaultCipherHandler cipherHandler, Serializable saltSource,
                                 String password, TextImageRenderer renderer, int height, int width, boolean addSelfReference) {
        TextCaptcha captcha = null;
        BufferedImage image = renderer.render(captchaText, height, width);
        try {
            byte[] imgData = convertImageToByteArray(image, IMG_FORMAT);
            CompletableFuture<String> selfreference = CompletableFuture.completedFuture(StringUtils.EMPTY);
            if (addSelfReference) {
                selfreference = CompletableFuture.supplyAsync(() -> makeSelfReference(cipherHandler, saltSource, password));
            }
            CompletableFuture<byte[]> encryptedToken = CompletableFuture.supplyAsync(() -> cipherHandler.encryptString(captchaText.getBytes(), password, saltSource));
            String tokenString = Base64.getEncoder().encodeToString(encryptedToken.get());
            captcha = new TextCaptcha(imgData, tokenString + selfreference.get());
        } catch (InterruptedException e) {
            log.fatal("Thread interruption during captcha generation: " + e.getLocalizedMessage());

        } catch (ExecutionException e) {
            log.fatal("Fatal error during captcha generation: " + e.getLocalizedMessage());
        }
        return captcha;
    }

    @Override
    public boolean validate(String answer, String token, DefaultCipherHandler cipherHandler, Serializable saltSource,
                            String password) {
        byte[] decoded = Base64.getDecoder().decode(token);

        byte[] decryptedToken = cipherHandler.decryptString(decoded, password, saltSource);
        return answer.equals(new String(decryptedToken));

    }

}
