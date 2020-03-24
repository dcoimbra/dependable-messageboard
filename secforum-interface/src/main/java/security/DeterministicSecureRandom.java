package security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * Creates a deterministic secure random generator based on a seed
 */
public class DeterministicSecureRandom {

    private SecureRandom secureRandom;

    private static String ALGORITHM = "SHA1PRNG";
    private static int N_BYTES_SALT = 20;


    public DeterministicSecureRandom(byte[] seed){

        try {
            this.secureRandom = SecureRandom.getInstance(ALGORITHM);
            this.secureRandom.setSeed(seed);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }



    /**
     * Get next deterministic number
     * @return Byte array
     */
    public byte[] getNext(){

        byte[] array = new byte[N_BYTES_SALT];
        this.secureRandom.nextBytes(array);

        return array;
    }
}
