package security;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

public class Utils {
    public static PrivateKey loadPrivateKey(String id) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        return (PrivateKey) keystore.getKey("client" + id, ("client" + id).toCharArray());
    }

    public static PublicKey loadPublicKey(String id) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {

        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        Certificate cert = keystore.getCertificate("client" + id);
        return cert.getPublicKey();
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
