package io.github.yaforster.flexcaptcha.textbased.rendering.impl;

import io.github.yaforster.flexcaptcha.textbased.rendering.TextImageRenderer;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * Example implementation.
 * <p>
 * Renders a text captcha image with a background image.
 *
 * @author Yannick Forster
 */
@RequiredArgsConstructor
public class BackgroundPictureTextImageRenderer extends SimpleTextImageRenderer implements TextImageRenderer {

    @NonNull
    BufferedImage backgroundimg;

    @Override
    public BufferedImage render(final String captchaTextInput, int height, int width) {
        if (StringUtils.isEmpty(captchaTextInput)) {
            throw new IllegalArgumentException("The specified captcha string is empty.");
        }
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphic = image.createGraphics();
        graphic.setColor(backgrndCol);
        graphic.drawImage(backgroundimg, null, 0, 0);
        drawDistortions(height, width, graphic);
        drawText(captchaTextInput, image);
        graphic.dispose();
        return image;
    }


}
