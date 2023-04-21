package io.github.yaforster.flexcaptcha.imgbased.handling.impl;

import io.github.yaforster.flexcaptcha.DefaultCipherHandler;
import io.github.yaforster.flexcaptcha.imgbased.ImageCaptcha;
import io.github.yaforster.flexcaptcha.imgbased.handling.ImageCaptchaHandler;
import org.junit.Test;
import org.mockito.Mockito;

import javax.crypto.spec.IvParameterSpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.stream.Stream;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

/**
 * Tests {@link SimpleImageCaptchaHandler}
 *
 * @author Yannick Forster
 */
public class SimpleImageCaptchaHandlerTest {

    final ImageCaptchaHandler handler = new SimpleImageCaptchaHandler();
    final BufferedImage[] dummyArr = new BufferedImage[]{new BufferedImage(10, 10, BufferedImage.TYPE_3BYTE_BGR)};
    final BufferedImage[] dummyArr2 = new BufferedImage[]{new BufferedImage(15, 15, BufferedImage.TYPE_4BYTE_ABGR)};
    final Serializable dummySerializable = (Serializable) Mockito.mock(Object.class, Mockito.withSettings().serializable());
    final String password = "ThisIsMyPassword!";
    final DefaultCipherHandler cipherHandler = getCHMock();

    @Test
    public void testAllNull() {
        assertThrows(IllegalArgumentException.class, () -> handler.generate(0, cipherHandler, null, null, null, null, 0, 0, true));
    }

    @Test
    public void testGridWidth0_ShouldFail() {
        assertThrows(IllegalArgumentException.class, () -> handler.generate(0, cipherHandler, dummySerializable, password,
                dummyArr, dummyArr2, true));
    }

    @Test
    public void testGridWidth1_ShouldFail() {
        assertThrows(IllegalArgumentException.class, () -> handler.generate(1, cipherHandler, dummySerializable, password,
                dummyArr, dummyArr2, true));
    }

    @Test
    public void manualResizeTest30x10() {
        BufferedImage smallImage = new BufferedImage(10, 10, BufferedImage.TYPE_3BYTE_BGR);
        BufferedImage largeImage = new BufferedImage(10, 30, BufferedImage.TYPE_3BYTE_BGR);
        BufferedImage[] images = new BufferedImage[]{smallImage, largeImage};
        ImageCaptcha captcha = handler.generate(2, cipherHandler, dummySerializable,
                password, images, images, 30, 10, true);
        BufferedImage[] resizedImages = getResizedImages(captcha);
        assertTrue(captcha.getToken().length() > 0);
        assertTrue(Stream.of(resizedImages).allMatch(img -> (img.getHeight() == 30 && img.getWidth() == 10)));
    }

    @Test
    public void manualResizeTest30x30() {
        BufferedImage smallImage = new BufferedImage(10, 10, BufferedImage.TYPE_3BYTE_BGR);
        BufferedImage largeImage = new BufferedImage(10, 30, BufferedImage.TYPE_3BYTE_BGR);
        BufferedImage[] images = new BufferedImage[]{smallImage, largeImage};
        ImageCaptcha captcha = handler.generate(2, cipherHandler, dummySerializable,
                password, images, images, 30, 30, true);
        BufferedImage[] resizedImages = getResizedImages(captcha);
        assertTrue(captcha.getToken().length() > 0);
        assertTrue(Stream.of(resizedImages).allMatch(img -> (img.getHeight() == 30 && img.getWidth() == 30)));
    }

    @Test
    public void manualResizeTest10x30() {
        BufferedImage smallImage = new BufferedImage(10, 10, BufferedImage.TYPE_3BYTE_BGR);
        BufferedImage largeImage = new BufferedImage(10, 30, BufferedImage.TYPE_3BYTE_BGR);
        BufferedImage[] images = new BufferedImage[]{smallImage, largeImage};
        ImageCaptcha captcha = handler.generate(2, cipherHandler, dummySerializable,
                password, images, images, 10, 30, true);
        BufferedImage[] resizedImages = getResizedImages(captcha);
        assertTrue(captcha.getToken().length() > 0);
        assertTrue(Stream.of(resizedImages).allMatch(img -> (img.getHeight() == 10 && img.getWidth() == 30)));
    }

    private BufferedImage[] getResizedImages(ImageCaptcha captcha) {
        return Stream.of(captcha.getImgData()).map(data -> {
            try {
                ByteArrayInputStream stream = new ByteArrayInputStream(data);
                return ImageIO.read(stream);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }).toArray(BufferedImage[]::new);
    }

    private DefaultCipherHandler getCHMock() {
        DefaultCipherHandler cipherHandler = Mockito.mock(DefaultCipherHandler.class);
        Mockito.when(cipherHandler.generateIV())
                .thenReturn(new IvParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
        Mockito.when(cipherHandler.decryptString(any(byte[].class), anyString(), any()))
                .thenReturn(new byte[]{1, 2, 3});
        Mockito.when(cipherHandler.encryptString(any(byte[].class), anyString(), any(), any(byte[].class)))
                .thenReturn(new byte[]{1, 2, 3});
        return cipherHandler;
    }

}
