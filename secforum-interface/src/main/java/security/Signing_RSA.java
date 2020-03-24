package security;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;

import static java.nio.charset.StandardCharsets.UTF_8;


public class Signing_RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;


    private static String ALGORITHM = "RSA";
    private static String SIGNING_ALGORITHM = "SHA256withRSA";
    private static int KEY_SIZE = 2048;


    private static String FILENAME_PRIVATE_PEM_FILE = "id_rsa";
    private static String FILENAME_PUBLIC_PEM_FILE = "id_rsa.pub";

    private static String RESOURCES_PATH = "src/main/resources/";


    private void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    private void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    private void setKeys(KeyPair keys) {
        setPublicKey(keys.getPublic());
        setPrivateKey(keys.getPrivate());
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }


    /**
     * Encrypts some plaintext given
     *
     * @param plainText text to cipher
     * @param key       Public key used to encrypt
     * @return ciphered text
     */
    public static String encrypt(String plainText, PublicKey key) {

        byte[] array = encrypt(plainText.getBytes(UTF_8), key);
        return Base64.getEncoder().encodeToString(array);
    }


    /**
     * Encrypts some byte array given
     *
     * @param array byte array to cipher
     * @param key   Public key used to encrypt
     * @return ciphered byte array
     */
    public static byte[] encrypt(byte[] array, PublicKey key) {

        Cipher encryptCipher;
        byte[] cipherText = null;

        try {
            encryptCipher = Cipher.getInstance(ALGORITHM);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);

            cipherText = encryptCipher.doFinal(array);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return cipherText;
    }


    /**
     * Decrypts some cipher text given
     *
     * @param cipherText text to decipher
     * @param key        Private key used to decrypt
     * @return deciphered text
     */
    public static String decrypt(String cipherText, PrivateKey key) {

        byte[] array = Base64.getDecoder().decode(cipherText);
        return new String(decrypt(array, key), UTF_8);
    }


    /**
     * Decrypts some byte array given
     *
     * @param array byte array to decipher
     * @param key   Private key used to decrypt
     * @return deciphered byte array
     */
    public static byte[] decrypt(byte[] array, PrivateKey key) {

        try {
            Cipher decriptCipher = Cipher.getInstance(ALGORITHM);
            decriptCipher.init(Cipher.DECRYPT_MODE, key);
            return decriptCipher.doFinal(array);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    /**
     * Sign a plaintext
     *
     * @param plainText text to be signed
     * @param key       Private key used to sign
     * @return Signature of the text
     */
    public static String sign(String plainText, PrivateKey key) {

        byte[] array = sign(plainText.getBytes(UTF_8), key);
        return Base64.getEncoder().encodeToString(array);
    }


    /**
     * Sign a byte array
     *
     * @param array byte array to be signed
     * @param key   Private key used to sign
     * @return Signature of the byte array
     */
    public static byte[] sign(byte[] array, PrivateKey key) {
        byte[] signature = null;

        try {
            Signature privateSignature = Signature.getInstance(SIGNING_ALGORITHM);
            privateSignature.initSign(key);
            privateSignature.update(array);

            signature = privateSignature.sign();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return signature;
    }


    /**
     * Verifies a signature of a plaintext
     *
     * @param plainText Plaintext original
     * @param signature Signature of the plaintext
     * @param key       Public key used to verify signature
     * @return True if the signature belongs to the given plaintext, False otherwise
     */
    public static boolean verify(String plainText, String signature, PublicKey key) {

        return verify(plainText.getBytes(UTF_8), Base64.getDecoder().decode(signature), key);
    }


    /**
     * Verifies a signature of a byte array
     *
     * @param array     Byte array original
     * @param signature Signature of the array
     * @param key       Public key used to verify signature
     * @return True if the signature belongs to the given bye array, False otherwise
     */
    public static boolean verify(byte[] array, byte[] signature, PublicKey key) {

        try {
            Signature publicSignature = Signature.getInstance(SIGNING_ALGORITHM);
            publicSignature.initVerify(key);
            publicSignature.update(array);

            return publicSignature.verify(signature);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}