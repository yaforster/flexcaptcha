package io.github.yaforster.flexcaptcha.textbased.rendering.impl;

import io.github.yaforster.flexcaptcha.textbased.rendering.TextImageRenderer;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apache.commons.lang3.StringUtils;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.stream.IntStream;

/**
 * Example implementation.
 * <p>
 * Renders a text captcha image without visual distortions in the finished
 * image.
 *
 * @author Yannick Forster
 */
@SuppressWarnings("DuplicatedCode")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class CleanTextImageRenderer implements TextImageRenderer {

    /**
     * Color of the Captcha Background
     */
    private Color backgrndCol = Color.white;
    /**
     * Set of possible colors of the letters in the captcha image
     */
    private Color[] textCols = new Color[]{Color.blue};

    /**
     * The name of the font used to draw the letters
     */
    private String fontName = "Verdana";

    /**
     * Renders a captcha image of specified height and widght of the given string
     */
    @Override
    public BufferedImage render(final String captchaTextInput, int height, int width) {
        if (StringUtils.isEmpty(captchaTextInput)) {
            throw new IllegalArgumentException("The specified captcha string is empty.");
        }
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphic = image.createGraphics();
        graphic.setColor(backgrndCol);
        graphic.fillRect(0, 0, width, height);
        drawText(captchaTextInput, image);
        graphic.dispose();
        return image;
    }

    /**
     * prepares the writing of the given captcha text onto the specified Graphics2d
     * object
     *
     * @param captchaTextInput string containing the text to write
     * @param image            the image on which to draw
     */
    private void drawText(String captchaTextInput, BufferedImage image) {
        Graphics2D graphic = image.createGraphics();
        Font textFont = new Font(fontName, Font.BOLD, (int) (image.getHeight() / 2.5));
        graphic.setColor(pickRandomColor(textCols));
        graphic.setFont(textFont);
        FontMetrics fontMetrics = graphic.getFontMetrics();
        int margin = image.getWidth() / 16;
        int chars = captchaTextInput.length();
        float spaceForLetters = (-margin << 1) + image.getWidth();
        float spacePerChar = spaceForLetters / (chars - 1.0f);
        IntStream.range(0, chars).boxed().forEachOrdered(i -> {
            char charToDraw = captchaTextInput.charAt(i);
            drawCharacter(image, textFont, fontMetrics, margin, spacePerChar, i, charToDraw);
        });
    }

    /**
     * Measures the font and draws each character of the given string to the
     * Graphics2D object at a randomized angle.
     *
     * @param image        the Graphics2D object containing the graphic in which the
     *                     image is constructed
     * @param textFont     Font object containing the font in which the characters
     *                     are to be drawn
     * @param fontMetrics  fontmetrics object used to measure the characters in the
     *                     string
     * @param margin       calculated based on the width to define an approximate
     *                     margin between each letter
     * @param spacePerChar the space that the entire string will approximately
     *                     require
     * @param index        running index of the character in the source string
     * @param charToDraw   the character to draw
     */
    private void drawCharacter(BufferedImage image, Font textFont, FontMetrics fontMetrics, int margin,
                               float spacePerChar, Integer index, char charToDraw) {
        int maxAdvance = fontMetrics.getMaxAdvance();
        int fontHeight = fontMetrics.getHeight();
        int charWidth = fontMetrics.charWidth(charToDraw);
        int charDim = Math.max(maxAdvance, fontHeight);
        BufferedImage charImage = new BufferedImage(charDim, charDim, BufferedImage.TYPE_INT_ARGB);
        Graphics2D charGraphics = charImage.createGraphics();
        charGraphics.setColor(pickRandomColor(textCols));
        charGraphics.setFont(textFont);
        int charX = (int) (0.5 * charDim - 0.5 * charWidth);
        charGraphics.drawString(String.valueOf(charToDraw), charX,
                (charDim - fontMetrics.getAscent()) / 2 + fontMetrics.getAscent());
        float x = margin + spacePerChar * (index.floatValue()) - charDim / 2.0f;
        int y = (image.getHeight() - charDim) / 2;
        image.createGraphics().drawImage(charImage, (int) x, y, charDim, charDim, null, null);
        charGraphics.dispose();
    }
}
