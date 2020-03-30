package security;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class Utils {
    public static PrivateKey loadPrivateKey(String id, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, password.toCharArray());
        return (PrivateKey) keystore.getKey("client" + id, password.toCharArray());
    }

    public static PublicKey loadPublicKey(String id) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {

        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        Certificate cert = keystore.getCertificate("client" + id);
        return cert.getPublicKey();
    }

    public static PublicKey loadPublicKeyFromCerificate(String filename) throws FileNotFoundException, CertificateException {
        FileInputStream fin = new FileInputStream(filename);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        return certificate.getPublicKey();
    }

    public static byte[] serialize(Object obj) {
        try (ByteArrayOutputStream b = new ByteArrayOutputStream()){
            try (ObjectOutputStream o = new ObjectOutputStream(b)){
                o.writeObject(obj);
            }
            return b.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] serializeMessage(List<Object> parameters) throws IOException {
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();

        for (Object parameter : parameters) {

            byte[] serializedParameter = serialize(parameter);
            if (serializedParameter != null)
                messageBytes.write(serializedParameter);
            else
                throw new IllegalArgumentException();
        }

        return messageBytes.toByteArray();
    }
}
