package secforum;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.io.IOException;

class KeyStoreGen {

    public static void main(String[] args) {
        try {
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(null, "sec".toCharArray());

            FileOutputStream fos = new FileOutputStream("keystorefile.jce");

            ks.store(fos, "sec".toCharArray());

            fos.close();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }
}