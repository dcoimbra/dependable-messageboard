package security;


import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

public class SigningSHA256_RSATests {

    private static PublicKey pubKey1;
    private static PublicKey pubKey2;
    private static PrivateKey privKey1;
    private static PrivateKey privKey2;
    private static byte[] txt = ("I want to encrypt something really important!!!").getBytes();

    @BeforeAll
    static void setup() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
            SecureRandom random2 = SecureRandom.getInstance("SHA1PRNG");

            generator.initialize(2048, random1);

            KeyPair pair1 = generator.generateKeyPair();
            pubKey1 = pair1.getPublic();
            privKey1 = pair1.getPrivate();

            generator.initialize(2048, random2);

            KeyPair pair2 = generator.generateKeyPair();
            pubKey2 = pair2.getPublic();
            privKey2 = pair2.getPrivate();


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    @Test
    void verifySignatureFromSameKeyPair() {

        byte[] signedTxt = SigningSHA256_RSA.sign(txt, privKey1);
        assertTrue(SigningSHA256_RSA.verify(txt, signedTxt, pubKey1));
    }


    @Test
    void verifySignatureFromDiffKeyPairs() {

        byte[] signedTxt = SigningSHA256_RSA.sign(txt, privKey1);
        assertFalse(SigningSHA256_RSA.verify(txt, signedTxt, pubKey2));
    }


    @Test
    void verifyDiffSignatureFromDiffKeys(){

        byte[] signed1 = SigningSHA256_RSA.sign(txt, privKey1);
        byte[] signed2 = SigningSHA256_RSA.sign(txt, privKey2);

        assertNotEquals(signed1, signed2);
    }

    @Test
    void verifySignedDataSize(){

        byte[] signed = SigningSHA256_RSA.sign(txt, privKey1);
        assertEquals(256, signed.length);    // RSA 2048 => encrypted data always with 256 bytes
    }


}
