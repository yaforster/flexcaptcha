package io.github.yaforster.flexcaptcha.textbased.rendering.impl;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import org.apache.commons.lang3.StringUtils;

import io.github.yaforster.flexcaptcha.textbased.rendering.TextImageRenderer;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * @author mavor
 *
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
		if(backgroundimg!=null) {
			graphic.drawImage(backgroundimg,null,0,0);
		}
		drawDistortions(height, width, graphic);
		drawText(captchaTextInput, image);
		graphic.dispose();
		return image;
	}


}
