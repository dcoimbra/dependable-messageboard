package secforum;

import security.Utils;

import java.io.*;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

public class NonceManager implements Serializable {
    private static Map<PublicKey, Integer> _nonces;
    private static String _filename = "src/main/resources/nonces.ser";
    private static String _backup = "src/main/resources/nonces_backup.ser";

    public NonceManager() {
        try {
            readNonces();
        } catch (FileNotFoundException e) {
            Map<PublicKey, Integer> nonces = new HashMap<>();

            try {
                for(int i = 1; i <= 3; i++) {
                    PublicKey pubKey = Utils.loadPublicKey(Integer.toString(i));
                    nonces.put(pubKey, 0);
                }
                writeNonces(nonces);
            } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException ex) {
                ex.printStackTrace();
            }

            _nonces = nonces;
        }
    }

    private static void setNonces(Map<PublicKey, Integer> nonces) {
        _nonces = nonces;
    }

    private static void readNonces() throws FileNotFoundException {
        try {
            FileInputStream file = new FileInputStream(_filename);
            ObjectInputStream in = new ObjectInputStream(file);

            Map<PublicKey, Integer> nonces = (Map<PublicKey, Integer>) in.readObject();
            in.close();
            file.close();

            NonceManager.setNonces(nonces);
        } catch (ClassNotFoundException | IOException e) {
            try {
                FileInputStream file_backup = new FileInputStream(_backup);
                ObjectInputStream backup_in = new ObjectInputStream(file_backup);

                Map<PublicKey, Integer> nonces = (Map<PublicKey, Integer>) backup_in.readObject();
                backup_in.close();
                file_backup.close();

                NonceManager.setNonces(nonces);
            } catch (FileNotFoundException fnfe) {
                throw fnfe;
            } catch (IOException | ClassNotFoundException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static void writeNonces(Map<PublicKey, Integer> nonces) throws IOException {
        FileOutputStream file = new FileOutputStream(_filename);
        ObjectOutputStream out = new ObjectOutputStream(file);

        out.writeObject(nonces);
        out.close();
        file.close();

        FileOutputStream backup = new FileOutputStream(_backup);
        ObjectOutputStream backup_out = new ObjectOutputStream(backup);

        backup_out.writeObject(nonces);
        backup_out.close();
        backup.close();
    }

    public Integer getClientNonce(PublicKey pubKey) {
        return _nonces.get(pubKey);
    }

    public void setClientNonce(PublicKey pubKey) {
        _nonces.put(pubKey, _nonces.get(pubKey) + 1);

        try {
            writeNonces(_nonces);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
