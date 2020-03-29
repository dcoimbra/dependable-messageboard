package security;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HashingMD5Tests {

    private static String ALGORITHM = "SHA1PRNG";



    @Test
    void generateSameHashFromSameString() {
        String txt = "random text...";

        String hash1 = HashingMD5.getDigest(txt);
        String hash2 = HashingMD5.getDigest(txt);

        assertEquals(hash1, hash2);
    }

    @Test
    void generateSameHashFromSameByteArray() {
        byte[] bytes = new byte[20];

        try {
            SecureRandom.getInstance(ALGORITHM).nextBytes(bytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] hash1 = HashingMD5.getDigest(bytes);
        byte[] hash2 = HashingMD5.getDigest(bytes);

        assertArrayEquals(hash1, hash2);
    }



    @Test
    void verifySizeOfHash() {
        byte[] bytes = new byte[500];

        try {
            SecureRandom.getInstance(ALGORITHM).nextBytes(bytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] hash1 = HashingMD5.getDigest(bytes);

        assertEquals(Objects.requireNonNull(hash1).length, 16); //MD5 => Digest of 16 bytes
    }



    @Test
    void verifyEquals() {
        String text = "This is a test string";

        String hash1 = HashingMD5.getDigest(text);
        String hash2 = HashingMD5.getDigest(text);

        assertTrue(HashingMD5.equals(hash1, hash2));
    }
}
