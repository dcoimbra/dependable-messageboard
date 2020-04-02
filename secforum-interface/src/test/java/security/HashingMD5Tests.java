package security;

import org.junit.jupiter.api.Test;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

public class HashingMD5Tests {

    private static String txt = "I want to digest a big message to prove that I can hash every message out there";


    @Test
    void generateSameHashFromSameString() {

        String hash1 = HashingMD5.getDigest(txt);
        String hash2 = HashingMD5.getDigest(txt);

        assertEquals(hash1, hash2);
    }

    @Test
    void generateSameHashFromSameByteArray() {
        byte[] bytes = txt.getBytes();

        byte[] hash1 = HashingMD5.getDigest(bytes);
        byte[] hash2 = HashingMD5.getDigest(bytes);

        assertArrayEquals(hash1, hash2);
    }



    @Test
    void verifySizeOfHash() {
        byte[] bytes = txt.getBytes();

        byte[] hash1 = HashingMD5.getDigest(bytes);

        assertEquals(Objects.requireNonNull(hash1).length, 32); //SHA-256 => Digest of 32 bytes
    }



    @Test
    void verifyEquals() {

        String hash1 = HashingMD5.getDigest(txt);
        String hash2 = HashingMD5.getDigest(txt);

        assertTrue(HashingMD5.equals(hash1, hash2));
    }
}
