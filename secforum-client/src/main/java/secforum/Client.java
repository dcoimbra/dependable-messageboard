package secforum;

import security.Signing_RSA;

import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client {
    String _id;
    PublicKey _publicKey;
    ForumInterface _forum;
    Scanner keyboardSc;


    public Client(String id) {
        try {
            _id = id;
            _publicKey = loadPublicKey(id);
            System.out.println(_publicKey);
            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
            System.out.println(_forum.hello("client"));
        } catch (RemoteException | NotBoundException | MalformedURLException e) {
            System.out.println(e.getMessage());
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        keyboardSc = new Scanner(System.in);
    }

    public void start() throws RemoteException {
        int command, nAnnouncement;
        String id, message;
        PublicKey publicKey;

        while (true) {
            System.out.println("1 - register\n2 - post\n3 - read\n4 - postGeneral\n5 - readGeneral\n6 - exit");

            try {

                command = Integer.parseInt(keyboardSc.nextLine());
                List<Announcement> quotedAnnouncements;
                PrivateKey privateKey;
                LocalDateTime timestamp;
                boolean success;

                switch (command) {
                    case 1:
                        if (!_forum.register(_publicKey)) {
                            System.out.println("Could not register due to write fail.");
                        }
                        break;

                    case 2:
                        if(_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter the message to be posted:");
                            message = keyboardSc.nextLine();
                            privateKey = loadPrivateKey(_id);
                            quotedAnnouncements = new ArrayList<>();
                            timestamp = LocalDateTime.now();
                            String signature = Signing_RSA.sign(_publicKey.toString() + message + quotedAnnouncements.toString() + timestamp.toString(), privateKey);
                            _forum.post(_publicKey, message, quotedAnnouncements, timestamp, signature);
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }

                        break;

                    case 3:
                        if(_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter client id:");
                            id = keyboardSc.nextLine();
                            publicKey = loadPublicKey(id);
                            privateKey = loadPrivateKey(_id);
                            System.out.println("Enter the number of announcements:");
                            nAnnouncement = Integer.parseInt(keyboardSc.nextLine());
                            String signature = Signing_RSA.sign(_publicKey.toString() + publicKey.toString() + Integer.toString(nAnnouncement), privateKey);
                            List<Announcement> list = _forum.read(_publicKey, publicKey, nAnnouncement, signature);

                            System.out.println("Got " + list.size() + " announcements!");
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }
                        break;

                    case 4:
                        if(_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter the message to be posted:");
                            message = keyboardSc.nextLine();
                            quotedAnnouncements = new ArrayList<>();
                            timestamp = LocalDateTime.now();
                            privateKey = loadPrivateKey(_id);
                            String signature = Signing_RSA.sign(_publicKey.toString() + message + quotedAnnouncements.toString() + timestamp.toString(), privateKey);
                            _forum.postGeneral(_publicKey, message, quotedAnnouncements, timestamp, signature);
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }

                        break;

                    case 5:
                        if (_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter the number of announcements:");
                            nAnnouncement = Integer.parseInt(keyboardSc.nextLine());
                            privateKey = loadPrivateKey(_id);
                            String signature = Signing_RSA.sign(_publicKey.toString() + Integer.toString(nAnnouncement), privateKey);
                            List<Announcement> listGeneral = _forum.readGeneral(_publicKey, nAnnouncement, signature);
                            System.out.println("Got " + listGeneral.size() + " announcements!");
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }
                        break;

                    case 6:
                        System.out.println("Thank you for using the app");
                        System.exit(0);


                    default:
                        System.out.println("ERROR. Must be between 1 and 6");
                        break;
                }
            } catch (NumberFormatException e) {
                System.out.println("ERROR. Must be number");
            } catch (RemoteException e) {
                System.out.println("ERROR. Server could not finish the operation. Try again");
                System.out.println(e.getMessage());
            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
    }

    public static PrivateKey loadPrivateKey(String id) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        return (PrivateKey) keystore.getKey("client" + id, ("client" + id).toCharArray());
    }

    public static PublicKey loadPublicKey(String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableKeyException {

        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        Certificate cert = keystore.getCertificate("client" + id);
        return cert.getPublicKey();
    }


    public static void main(String[] args) {
        Client c = new Client(args[0]);

        try {
            c.start();
        } catch (RemoteException re) {
            System.out.println(re.getMessage());
        }
    }
}
