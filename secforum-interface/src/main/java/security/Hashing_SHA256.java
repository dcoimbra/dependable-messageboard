package security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;


public class Hashing_SHA256 {

    private static final String ALGORITHM = "MD5";


    /**
     * Completes the hash computation of a text
     * @param text Text to hashed
     * @return Byte array with 32 bytes of the text hashed
     */
    public static String getDigest(String text){

        byte[] bytes = getDigest(text.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(bytes);
    }



    /**
     * Completes the hash computation of a byte array
     * @param array Byte array to hashed
     * @return Byte array with 32 bytes of the byte array hashed
     */
    public static byte[] getDigest(byte[] array){

        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
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
    public static boolean equals(String digest1, String digest2) {
        return MessageDigest.isEqual(Base64.getDecoder().decode(digest1), Base64.getDecoder().decode(digest2)   );
    }
}