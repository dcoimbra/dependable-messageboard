package security;

//import org.bouncycastle.util.io.pem.PemObject;
//import org.bouncycastle.util.io.pem.PemReader;
//import org.bouncycastle.util.io.pem.PemWriter;
import java.io.File;
import java.io.*;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class PemFile {

//    private PemObject pemObject;

    PemFile (){}

//    PemFile (Key key, String description) {
//        this.pemObject = new PemObject(description, key.getEncoded());
//    }


//    /**
//     * Writes a PEM Object into a PEM file
//     * @param filename Name of the file
//     * @throws FileNotFoundException In case of a creation of a new FileOutputStream
//     */
//    void writeKey (String filename) throws FileNotFoundException {
//        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
//
//        try {
//            pemWriter.writeObject(this.pemObject);
//            pemWriter.close();
//
//        }  catch (IOException e) {
//            e.printStackTrace();
//        }
//    }


//    /**
//     * Reads a public key from PEM file
//     * @param filepath Name of the file
//     * @param algorithm Algorithm used
//     * @return PublicKey inside the file
//     * @throws IOException In case of IOException in parsePEMFile
//     */
//    PublicKey readPublicKey (String filepath, String algorithm) throws IOException {
//        byte[] bytes = parsePEMFile(filepath);
//        return getPublicKey(bytes, algorithm);
//    }



//    /**
//     * Reads a private key from PEM file
//     * @param filepath Name of the file
//     * @param algorithm Algorithm used
//     * @return PrivateKey inside the file
//     * @throws IOException In case of IOException in parsePEMFile
//     */
//    PrivateKey readPrivateKey (String filepath, String algorithm) throws IOException {
//        byte[] bytes = parsePEMFile(filepath);
//        return getPrivateKey(bytes, algorithm);
//    }



//    /**
//     * Parse PEM file into byte array
//     * @param filename Name of the file
//     * @return Byte array
//     * @throws IOException In case of FileNotFoundException or IOException.
//     */
//    private byte[] parsePEMFile(String filename) throws IOException {
//        File pemFile = new File(filename);
//
//        if (!pemFile.isFile() || !pemFile.exists()) {
//            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
//        }
//
//        PemReader reader = new PemReader(new FileReader(pemFile));
//        PemObject pemObject = reader.readPemObject();
//        byte[] content = pemObject.getContent();
//
//        reader.close();
//        return content;
//    }



    /**
     * Gets public key from byte array
     * @param keyBytes Byte array of the key
     * @param algorithm Algorithm used to create the key
     * @return PublicKey inside the file
     */
    private PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
        PublicKey publicKey = null;

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");

        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }

        return publicKey;
    }



    /**
     * Gets private key from byte array
     * @param keyBytes Byte array of the key
     * @param algorithm Algorithm used to create the key
     * @return PrivateKey inside the file
     */
    private PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
        PrivateKey privateKey = null;

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm could not be found.");

        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
        }

        return privateKey;
    }
}