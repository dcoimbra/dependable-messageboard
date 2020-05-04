package security;

import java.security.*;

public class SigningSHA256_RSA {

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";


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