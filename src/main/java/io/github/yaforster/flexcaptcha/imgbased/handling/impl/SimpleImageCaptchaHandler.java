package io.github.yaforster.flexcaptcha.imgbased.handling.impl;

import io.github.yaforster.flexcaptcha.DefaultCipherHandler;
import io.github.yaforster.flexcaptcha.imgbased.ImageCaptcha;
import io.github.yaforster.flexcaptcha.imgbased.handling.ImageCaptchaHandler;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Provides basic captcha handling regarding generation of a simplistic visual
 * representation of the image-based captcha string as well as hashing the token
 * and salt object
 *
 * @author Yannick Forster
 */

public class SimpleImageCaptchaHandler implements ImageCaptchaHandler {

    /**
     * The image format
     */
    private static final String IMG_FORMAT = "PNG";
    /**
     * Log4J Logger
     */
    final Logger log = LogManager.getLogger(SimpleImageCaptchaHandler.class);

    /**
     * Generates the image captcha. Randomizes a grid layout with the images taken
     * from solutionImages and otherImages
     */
    public ImageCaptcha generate(int gridWidth, DefaultCipherHandler cipherHandler, Serializable saltSource, String password,
                                 BufferedImage[] solutionImages, BufferedImage[] fillImages, int height, int width, boolean addSelfReference) {
        if (solutionImages == null || solutionImages.length == 0) {
            throw new IllegalArgumentException("solutionImages can not be empty or null.");
        }
        if (fillImages == null || fillImages.length == 0) {
            throw new IllegalArgumentException("fillImages can not be empty or null.");
        }
        if (gridWidth <= 1) {
            throw new IllegalArgumentException("The gridWidth must be larger than 1.");
        }
        if (height <= 0) {
            throw new IllegalArgumentException("The height must be an integer larger than 0.");
        }
        if (width <= 0) {
            throw new IllegalArgumentException("The width must be an integer larger than 0.");
        }
        solutionImages = resizeImages(solutionImages, height, width);
        fillImages = resizeImages(fillImages, height, width);
        byte[][] gridData = new byte[gridWidth * gridWidth][];
        int halfGrid = Double.valueOf(Math.ceil(gridData.length / 2f)).intValue();
        int[] gridIndices = IntStream.range(0, gridData.length).boxed().mapToInt(i -> i).toArray();
        ArrayUtils.shuffle(gridIndices);
        int[] solutionIndices = Arrays.copyOfRange(gridIndices, 0, halfGrid);
        Arrays.sort(solutionIndices);
        int[] fillIndices = ArrayUtils.removeElements(gridIndices, solutionIndices);
        return makeImageCaptcha(saltSource, cipherHandler, password, solutionImages, fillImages, gridData, solutionIndices,
                fillIndices, addSelfReference);
    }

    /**
     * Checks if the given answer is correct
     */
    @Override
    public boolean validate(String answer, String token, DefaultCipherHandler cipherHandler, Serializable saltSource, String password) {
        return token.split(DELIMITER)[0].equals(makeToken(answer, saltSource));
    }

    /**
     * Resizes all images to the height and width specified
     *
     * @param allImages The {@link BufferedImage}s to resize
     * @param height    the target height to resize
     * @param width     the target width to resize
     * @return array of resized {@link BufferedImage}s
     */
    private BufferedImage[] resizeImages(BufferedImage[] allImages, int height, int width) {
        return Stream.of(allImages).map(img -> {
            Image imageObj = img.getScaledInstance(width, height, img.getType());
            BufferedImage dimg = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g2d = dimg.createGraphics();
            g2d.drawImage(imageObj, 0, 0, null);
            g2d.dispose();
            return dimg;
        }).toArray(BufferedImage[]::new);
    }

    /**
     * Generates the completed captcha object with a picture grid based on the
     * specified gridsize, solution pictures and fill pictures. The salt source
     * specifies an arbitrary object used to salt the token.
     *
     * @param saltSource      arbitrary object to be used to salt the solution hash
     *                        for added security and to allow for authenticating the
     *                        given answer
     * @param password        the password used to encrypt the implementation
     *                        reference
     * @param solutionImages  the "correct" images that the user is supposed to
     *                        select
     * @param fillImages      all images that are not the solution
     * @param gridData        Array of byte arrays which is filled with the images
     *                        or null if one of the images could not be loaded into
     *                        the grid.
     * @param solutionIndices the indices to fill with correct images
     * @param fillIndices     the indices to fill with filler images
     * @return {@link ImageCaptcha} containing the finalized captcha
     */
    private ImageCaptcha makeImageCaptcha(Serializable saltSource, DefaultCipherHandler cipherHandler, String password, BufferedImage[] solutionImages,
                                          BufferedImage[] fillImages, byte[][] gridData, int[] solutionIndices, int[] fillIndices, boolean addSelfReference) {
        gridData = fillGridWithImages(gridData, solutionImages, solutionIndices);
        gridData = fillGridWithImages(gridData, fillImages, fillIndices);
        if (gridData == null || Stream.of(gridData).anyMatch(Objects::isNull)) {
            return null;
        }
        String token = generateToken(cipherHandler, saltSource, password, solutionIndices, addSelfReference);
        return new ImageCaptcha(gridData, token);
    }

    /**
     * Iterates over all indices and puts the byte data of a random image picked in
     * the corresponding element of gridData.
     *
     * @param gridData      Array of byte arrays holding the image data
     * @param imagesToAdd   Array of images representing a pool from which the
     *                      gridData is populated.
     * @param indicesToFill The indices into which images from the imagesToAdd-Array
     *                      are filled
     * @return Array of byte arrays which is filled with the images or null if one
     * of the images could not be loaded into the grid.
     */
    private byte[][] fillGridWithImages(byte[][] gridData, BufferedImage[] imagesToAdd, int[] indicesToFill) {
        if (gridData != null) {
            IntStream.of(indicesToFill).forEach(i -> {
                try {
                    int rndIndex = ThreadLocalRandom.current().nextInt(imagesToAdd.length);
                    BufferedImage solutionImg = imagesToAdd[rndIndex];
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    ImageIO.write(solutionImg, IMG_FORMAT, bos);
                    byte[] bytes = bos.toByteArray();
                    gridData[i] = bytes;
                } catch (IOException e) {
                    log.fatal("Could not write loaded image to byte array during grid filling. " + e.getMessage());
                }
            });
        }
        return gridData;
    }

    /**
     * Generates the token from the saltsource and the indices of the solution (the
     * correct ones)
     *
     * @param saltSource      Object used during creation of the captcha token to
     *                        ensure authenticity
     * @param password        the password used to encrypt the implementation
     *                        reference
     * @param solutionIndices the correct indices in the captcha
     * @return String of the token
     */
    private String generateToken(DefaultCipherHandler cipherHandler, Serializable saltSource, String password, int[] solutionIndices, boolean addSelfReference) {
        Arrays.sort(solutionIndices);
        String solution = Arrays.toString(solutionIndices).replaceAll("\\s+", "");
        String token = makeToken(solution, saltSource);
        if (addSelfReference) {
            token += makeSelfReference(cipherHandler, saltSource, password);
        }
        return token;
    }

}
