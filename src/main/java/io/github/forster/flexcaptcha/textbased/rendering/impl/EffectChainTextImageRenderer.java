package de.forster.flexcaptcha.textbased.rendering.impl;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;

import com.jhlabs.image.AbstractBufferedImageOp;

import de.forster.flexcaptcha.textbased.rendering.TextImageRenderer;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain=true)
public class EffectChainTextImageRenderer implements TextImageRenderer {
	
	/**
	 * Set of possible colors of the letters in the captcha image
	 */
	Color[] textCols = new Color[] {Color.blue, Color.red, Color.darkGray, Color.magenta, Color.black};
	
	/**
	 * List of operations that will be applied to the image during rendering.
	 */
	List<AbstractBufferedImageOp> bufferedOps = new ArrayList<AbstractBufferedImageOp>();
	
	@Override
	public BufferedImage render(final String captchaTextInput, int height, int width) {
		BufferedImage image = new SimpleTextImageRenderer().render(captchaTextInput, height, width);
		if(!bufferedOps.isEmpty()) {
			image = applyFilters(image);
		}
		return image;
	}

	private BufferedImage applyFilters(BufferedImage image) {
		bufferedOps.forEach(op -> op.filter(image, image));
		return image;
	}
}