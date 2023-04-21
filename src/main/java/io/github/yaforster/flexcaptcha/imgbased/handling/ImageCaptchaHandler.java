package io.github.yaforster.flexcaptcha.imgbased.handling;

import io.github.yaforster.flexcaptcha.CaptchaHandler;
import io.github.yaforster.flexcaptcha.DefaultCipherHandler;
import io.github.yaforster.flexcaptcha.imgbased.ImageCaptcha;
import org.apache.commons.lang3.ArrayUtils;

import java.awt.image.BufferedImage;
import java.io.Serializable;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Interface for defining the methods for image captcha handlers besides
 * offering default logic for resizing the images from the input, to allow for
 * clean display in a grid
 *
 * @author Yannick Forster
 */
public interface ImageCaptchaHandler extends CaptchaHandler {

    /**
     * /** Generates an image-based captcha, forming a square-shaped grid with the
     * height being the same as the grid width. The captcha will contain the byte
     * data of the pictures in the grid, with the token being formed from the
     * positions of the images that were taken from the solutionImages-Array while
     * all other positions are filled with other images. This method determines the
     * largest height and width of all the loaded images (both in solutionImages and
     * otherImages) and uses those values to resize every image to achieve uniform
     * dimensions.
     *
     * @param gridWidth      The width of the grid of images. The grid is square
     *                       shaped, so a size of 3 will result in 9 cells making up
     *                       a grid of 3x3.
     * @param cipherHandler  {@link DefaultCipherHandler} object used to handle the
     *                       encryption of the token itself and the self reference
     *                       part inside the token
     * @param saltSource     A {@link Serializable} used to salt the token.
     * @param password       the password used to encrypt the implementation
     *                       reference
     * @param solutionImages Array of {@link BufferedImage}s used as the correct
     *                       images in the grid
     * @param fillImages     Array of {@link BufferedImage}s used as the wrong
     *                       images in the grid, filling the grid at every position
     *                       not containing an image from the solutionImages array.
     * @return {@link ImageCaptcha} object containing the hashed solution and the
     * grid as array of byte arrays.
     */
    default ImageCaptcha generate(int gridWidth, DefaultCipherHandler cipherHandler, Serializable saltSource,
                                  String password, BufferedImage[] solutionImages, BufferedImage[] fillImages, boolean addSelfReference) {
        BufferedImage[] allImages = ArrayUtils.addAll(solutionImages, fillImages);
        if (solutionImages == null || solutionImages.length == 0) {
            throw new IllegalArgumentException("solutionImages can not be empty or null.");
        }
        if (fillImages == null || fillImages.length == 0) {
            throw new IllegalArgumentException("fillImages can not be empty or null.");
        }
        int largestHeight = getLargestHeight(allImages);
        int largestwidth = getLargestWidth(allImages);
        return generate(gridWidth, cipherHandler, saltSource, password, solutionImages, fillImages, largestHeight,
                largestwidth, addSelfReference);
    }

    /**
     * /** Generates an image-based captcha, forming a square-shaped grid with the
     * height being the same as the grid width. The captcha will contain the byte
     * data of the pictures in the grid, with the token being formed from the
     * positions of the images that were taken from the solutionImages-Array while
     * all other positions are filled with other images.
     *
     * @param gridWidth      The width of the grid of images. The grid is square
     *                       shaped, so a size of 3 will result in 9 cells making up
     *                       a grid of 3x3.
     * @param cipherHandler  {@link DefaultCipherHandler} object used to handle the
     *                       encryption of the token itself and the self reference
     *                       part inside the token
     * @param saltSource     A {@link Serializable} used to salt the token.
     * @param password       the password used to encrypt the implementation
     *                       reference
     * @param solutionImages Array of {@link BufferedImage}s used as the correct
     *                       images in the grid
     * @param fillImages     Array of {@link BufferedImage}s used as the wrong
     *                       images in the grid, filling the grid at every position
     *                       not containing an image from the solutionImages array.
     * @param imageHeight    the height to which every image is resized to fit the
     *                       grid
     * @param imageWidth     the width to which every image is resized to fit the
     *                       grid
     * @return {@link ImageCaptcha} object containing the hashed solution and the
     * grid as array of byte arrays.
     */
    ImageCaptcha generate(int gridWidth, DefaultCipherHandler cipherHandler, Serializable saltSource, String password,
                          BufferedImage[] solutionImages, BufferedImage[] fillImages, int imageHeight, int imageWidth, boolean addSelfReference);

    /**
     * Gets the largest height out of all the {@link BufferedImage}s
     *
     * @param allImages array of {@link BufferedImage}s to check
     * @return int the height of the image with the largest height
     */
    private int getLargestHeight(BufferedImage[] allImages) {
        Optional<BufferedImage> greatestHeight = Stream.of(allImages)
                .max(Comparator.comparing(BufferedImage::getHeight));
        return greatestHeight.map(BufferedImage::getHeight).orElse(Optional.of(allImages[0].getWidth()).orElse(100));
        /* Fallback in case comparing the images does not work. */
    }

    /**
     * Gets the largest width out of all the {@link BufferedImage}s
     *
     * @param allImages array of {@link BufferedImage}s to check
     * @return int the width of the image with the largest width
     */
    private int getLargestWidth(BufferedImage[] allImages) {
        Optional<BufferedImage> greatestWidth = Stream.of(allImages).max(Comparator.comparing(BufferedImage::getWidth));
        return greatestWidth.map(BufferedImage::getWidth).orElse(Optional.of(allImages[0].getWidth()).orElse(100));
        /* Fallback in case comparing the images does not work. */
    }

}
