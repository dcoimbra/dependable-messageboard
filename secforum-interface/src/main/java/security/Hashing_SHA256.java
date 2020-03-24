package security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class Hashing_SHA256 {

    private static final String ALGORITHM = "SHA-256";
    public static final int N_BYTES_SALT = 20;



    /**
     * Completes the hash computation of a text
     * @param text Text to hashed
     * @param salt Salt used to update the digest
     * @return Byte array with 32 bytes of the text hashed
     */
    public static byte[] getDigest(String text, byte[] salt){

        return getDigest(text.getBytes(StandardCharsets.UTF_8), salt);
    }



    /**
     * Completes the hash computation of a byte array
     * @param array Byte array to hashed
     * @param salt Salt used to update the digest
     * @return Byte array with 32 bytes of the byte array hashed
     */
    public static byte[] getDigest(byte[] array, byte[] salt){

        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            md.update(salt);
            return md.digest(array);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }



    /**
     * Compares two digests for equality.
     * @param digest1 One of the digests to compare
     * @param digest2  The other digest to compare
     * @return True if the digests are equal, false otherwise.
     */
    public static boolean equals (byte[] digest1, byte[] digest2) {

        return MessageDigest.isEqual(digest1, digest2);
    }



    /**
     * Generate a pseudorandom numbers with 20 bytes
     * @return Byte array with pseudorandom numbers
     */
    public static byte[] generateSalt() {

        SecureRandom sr = new SecureRandom();

        byte[] salt = new byte[N_BYTES_SALT];
        sr.nextBytes(salt);

        return salt;
    }
}