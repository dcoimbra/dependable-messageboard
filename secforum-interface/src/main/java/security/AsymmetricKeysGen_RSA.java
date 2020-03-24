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


public class AsymmetricKeysGen_RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;


    private static String ALGORITHM = "RSA";
    private static String SIGNING_ALGORITHM = "SHA256withRSA";
    private static int KEY_SIZE = 2048;


    private static String FILENAME_PRIVATE_PEM_FILE = "id_rsa";
    private static String FILENAME_PUBLIC_PEM_FILE = "id_rsa.pub";

    private static String RESOURCES_PATH = "src/main/resources/";



    private void setPrivateKey (PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    private void setPublicKey (PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    private void setKeys(KeyPair keys){
        setPublicKey(keys.getPublic());
        setPrivateKey(keys.getPrivate());
    }

    public PrivateKey getPrivateKey () {
        return privateKey;
    }

    public PublicKey getPublicKey () {
        return publicKey;
    }



    /**
     * Generate Keys specification
     * @return HasMap with keys' specification
     */
    public static HashMap<RSAKeysSpec, BigInteger> generateKeysSpec(){

        HashMap<RSAKeysSpec, BigInteger> values = new HashMap<>();
        SecureRandom random = new SecureRandom();

        // Choose two distinct prime numbers p and q.
        BigInteger p = BigInteger.probablePrime(KEY_SIZE /2, random);
        BigInteger q = BigInteger.probablePrime(KEY_SIZE /2, random);

        // Compute n = pq (modulus)
        BigInteger modulus = p.multiply(q);

        // Compute φ(n) = φ(p)φ(q) = (p − 1)(q − 1) = n - (p + q -1), where φ is Euler's totient function.
        // and choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1; i.e., e and φ(n) are coprime.
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger publicExponent = getCoprime(m,random);

        // Determine d as d ≡ e−1 (mod φ(n)); i.e., d is the multiplicative inverse of e (modulo φ(n)).
        BigInteger privateExponent = publicExponent.modInverse(m);

        values.put(RSAKeysSpec.modulus, modulus);
        values.put(RSAKeysSpec.publicExponent, publicExponent);
        values.put(RSAKeysSpec.privateExponent, privateExponent);

        return values;
    }



    /**
     * Generate RSA public and private keys pairs from RSA values specifications
     * @param values HasMap with the keys' specifications
     * @return Public and private keys pairs
     */
    public KeyPair generateKeys(HashMap<RSAKeysSpec, BigInteger> values){

        return generateKeys(values.get(RSAKeysSpec.modulus), values.get(RSAKeysSpec.publicExponent),
                values.get(RSAKeysSpec.privateExponent));
    }



    /**
     * Generate RSA public and private keys pairs from RSA values specifications
     * @param modulus Modulus value for RSA
     * @param publicExponent Public exponent value for RSA
     * @param privateExponent Private exponent value for RSA
     * @return Public and private keys pairs. Null in case of Algorithm not available or invalid key specification
     */
    public KeyPair generateKeys(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent){

        // create private and public specifications
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, publicExponent);
        RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, privateExponent);

        try {
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);

            // generation key pair
            KeyPair keys = new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));

            setKeys(keys);
            return keys;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }



    /**
     * Get a coprime of a BigInteger
     * @param m BigInteger
     * @param random An instance of this class is used to generate a stream of pseudorandom numbers
     * @return Coprime of m
     */
    private static BigInteger getCoprime(BigInteger m, SecureRandom random) {

        int length = m.bitLength() - 1;
        BigInteger e = BigInteger.probablePrime(length,random);

        while (! (m.gcd(e)).equals(BigInteger.ONE) ) {
            e = BigInteger.probablePrime(length,random);
        }
        return e;
    }



    /**
     * Writes down private and public keys into a PEM file
     */
    public void writeKeys(){
        writePemFile(privateKey, "RSA PRIVATE KEY", FILENAME_PRIVATE_PEM_FILE);
        writePemFile(publicKey, "RSA PUBLIC KEY", FILENAME_PUBLIC_PEM_FILE);
    }



    /**
     * Writes a key into a PEM file
     * @param key Key to be saved
     * @param description Description of the key
     * @param filename Name of the file
     */
    private void writePemFile(Key key, String description, String filename) {
        PemFile pemFile = new PemFile(key, description);

        try {
            new File(RESOURCES_PATH).mkdirs();
            pemFile.writeKey(RESOURCES_PATH + filename);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }



    /**
     * Reads private and public keys from PEM file
     * @return KeyPair with public and private keys. Null in case of file inexistence
     */
    public KeyPair readKeys(){
        PemFile pemFile = new PemFile();

        try {
            // reads private and public keys
            PublicKey publicKey = pemFile.readPublicKey(RESOURCES_PATH + FILENAME_PUBLIC_PEM_FILE, ALGORITHM);
            PrivateKey privateKey = pemFile.readPrivateKey(RESOURCES_PATH + FILENAME_PRIVATE_PEM_FILE, ALGORITHM);

            return new KeyPair(publicKey, privateKey);

        } catch (IOException e) {
            //e.printStackTrace();
        }
        return null;
    }



    /**
     * Encrypts some plaintext given
     * @param plainText text to cipher
     * @param key Public key used to encrypt
     * @return ciphered text
     */
    public static String encrypt(String plainText, PublicKey key) {

        byte[] array = encrypt(plainText.getBytes(UTF_8), key);
        return Base64.getEncoder().encodeToString(array);
    }



    /**
     * Encrypts some byte array given
     * @param array byte array to cipher
     * @param key Public key used to encrypt
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
     * @param cipherText text to decipher
     * @param key Private key used to decrypt
     * @return deciphered text
     */
    public static String decrypt(String cipherText, PrivateKey key) {

        byte[] array = Base64.getDecoder().decode(cipherText);
        return new String(decrypt(array, key), UTF_8);
    }



    /**
     * Decrypts some byte array given
     * @param array byte array to decipher
     * @param key Private key used to decrypt
     * @return deciphered byte array
     */
    public static byte[] decrypt(byte[] array, PrivateKey key) {

        try{
            Cipher decriptCipher = Cipher.getInstance(ALGORITHM);
            decriptCipher.init(Cipher.DECRYPT_MODE, key);
            return decriptCipher.doFinal(array);

        } catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }




    /**
     * Sign a plaintext
     * @param plainText text to be signed
     * @param key Private key used to sign
     * @return Signature of the text
     */
    public static String sign(String plainText, PrivateKey key){

        byte[] array =  sign(plainText.getBytes(UTF_8), key);
        return Base64.getEncoder().encodeToString(array);
    }



    /**
     * Sign a byte array
     * @param array byte array to be signed
     * @param key Private key used to sign
     * @return Signature of the byte array
     */
    public static byte[] sign(byte[] array, PrivateKey key){
        byte[] signature = null;

        try{
            Signature privateSignature = Signature.getInstance(SIGNING_ALGORITHM);
            privateSignature.initSign(key);
            privateSignature.update(array);

            signature = privateSignature.sign();

        } catch (Exception e){
            e.printStackTrace();
        }

        return signature;
    }



    /**
     * Verifies a signature of a plaintext
     * @param plainText Plaintext original
     * @param signature Signature of the plaintext
     * @param key Public key used to verify signature
     * @return True if the signature belongs to the given plaintext, False otherwise
     */
    public static boolean verify(String plainText, String signature, PublicKey key) {

        return verify(plainText.getBytes(UTF_8), Base64.getDecoder().decode(signature), key);
    }



    /**
     * Verifies a signature of a byte array
     * @param array Byte array original
     * @param signature Signature of the array
     * @param key Public key used to verify signature
     * @return True if the signature belongs to the given bye array, False otherwise
     */
    public static boolean verify(byte[] array, byte[] signature, PublicKey key) {

        try{
            Signature publicSignature = Signature.getInstance(SIGNING_ALGORITHM);
            publicSignature.initVerify(key);
            publicSignature.update(array);

            return publicSignature.verify(signature);

        } catch (Exception e){
            e.printStackTrace();
        }

        return false;
    }


    /**
     * This method will serialize a PublicKey object into
     * a byte array one, so that we can apply the OTP techenique
     * on the object.
     * @param key - The public key that will be serialized
     * @return A byte array containing the result of the
     * serialization
     */
    public static byte[] serialize(HashMap<RSAKeysSpec, BigInteger> key) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(out);

            os.writeObject(key);
            return out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * This method will deserialize a byte array into
     * a PublicKey object, so that we can get the object after
     * performing the OTP technique.
     * @param data - The data that will be deserialized
     * @return A public key that was deserialized from the
     * byte array data
     */
    public static HashMap<RSAKeysSpec, BigInteger> deserialize(byte[] data) {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            ObjectInputStream is = new ObjectInputStream(in);

            return (HashMap<RSAKeysSpec, BigInteger>) is.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return null;
    }
}
