# flexcaptcha
A minimalistic CAPTCHA generator and validator, with customizable rendering options ready for both web and desktop applications. The image manipulation is done through [https://github.com/ajmas/JH-Labs-Java-Image-Filters](https://github.com/ajmas/JH-Labs-Java-Image-Filters).

## Usage
### text-based CAPTCHA:

```java
    SimpleCaptchaTextGenerator generator = new SimpleCaptchaTextGenerator(); //Can generate randomized strings from a pool of allowed characters
    String s = generator.generate(10, Case.UPPERCASE); //Here is my random string. I want all letters to be uppercase. lowercase and mixed-case is supported, too. Or you supply your own string.
    String pw = "ThisIsMyPassword"; //Supply a password for encryption
    
    SimpleTextImageRenderer renderer = new SimpleTextImageRenderer(); //pick a renderer controlling the image generation (and distortion)
    CipherHandler ch = new CipherHandler(); //Cipherhandler for implementing the encryption and decryption
    
    TextCaptchaHandler handler = new SimpleTextCaptchaHandler();
    String saltSource = "Hello World!"; //A salt source for salting the hashes and encryption
    TextCaptcha captcha = handler.toCaptcha(s, ch, saltSource, pw, renderer , 100, 300); //putting it all together
```
#### Sample images:

![5W3QRKCYMY](https://user-images.githubusercontent.com/96397624/148242974-931e21b9-de0c-4200-ad99-41c3e3918228.png)

![B6JJRT9XSD](https://user-images.githubusercontent.com/96397624/148242976-62a6e567-f2e0-43cf-87ac-43ea03aef6a9.png)

![bbmsjgwf4w](https://user-images.githubusercontent.com/96397624/148242978-1037e9a1-7b19-48e7-86e3-8896bb33306d.png)

![FqF](https://user-images.githubusercontent.com/96397624/148242981-d7889d63-5850-40a7-b913-9f66b9fe478d.png)

![m43geumhk8](https://user-images.githubusercontent.com/96397624/148242983-53876334-f87f-483e-93c9-9f63ff958e8e.png)



### image-based CAPTCHA:

```java
    ImageCaptchaHandler handler = new SimpleImageCaptchaHandler();
    CipherHandler ch = new CipherHandler();
    ImageLoader loader = new ImageLoader();
    
    BufferedImage[] solutionImages = loader.getImagesfromPath("C:\\SomeDirectory");
    BufferedImage[] fillImages = loader.getImagesfromPath("C:\\SomeOtherDirectory");
    
    String saltSource = "Hello World!";
    int gridWidth = 3;
    ImageCaptcha captcha = handler.generate(gridWidth, ch, saltSource, password, solutionImages, fillImages);
```
## Dependency

```
<dependency>
    <groupId>io.github.yaforster</groupId>
    <artifactId>flexcaptcha</artifactId>
    <version>1.2.2</version>
</dependency>
```
