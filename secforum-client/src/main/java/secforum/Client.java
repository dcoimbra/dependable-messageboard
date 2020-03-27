package secforum;

import security.Signing_RSA;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client {
    private String _id;
    private PublicKey _publicKey;
    private PublicKey _serverKey;
    private ForumInterface _forum;
    private Scanner keyboardSc;


    public Client(String id) {
        try {
            _id = id;
            _publicKey = loadPublicKey(id);
            System.out.println(_publicKey);

            FileInputStream fin = new FileInputStream("src/main/resources/server.cer");
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
            _serverKey = certificate.getPublicKey();

            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
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
                Response res;
                String signature;

                switch (command) {
                    case 1: // register

                        res = _forum.register(_publicKey);
                        verifyResponse(res);

                        break;

                    case 2: // post
                        System.out.println("Enter the message to be posted:");
                        message = keyboardSc.nextLine();

                        //TODO: get list of announcement's IDs to quote
                        quotedAnnouncements = new ArrayList<>();
                        timestamp = LocalDateTime.now();
                        privateKey = loadPrivateKey(_id);
                        signature = Signing_RSA.sign(_publicKey.toString() + message + quotedAnnouncements.toString() + timestamp.toString(), privateKey);

                        res = _forum.post(_publicKey, message, quotedAnnouncements, timestamp, signature);
                        verifyResponse(res);

                        break;

                    case 3: // read
                        System.out.println("Enter client id:");
                        id = keyboardSc.nextLine();

                        publicKey = loadPublicKey(id);
                        privateKey = loadPrivateKey(_id);
                        System.out.println("Enter the number of announcements:");
                        nAnnouncement = Integer.parseInt(keyboardSc.nextLine());
                        signature = Signing_RSA.sign(_publicKey.toString() + publicKey.toString() + Integer.toString(nAnnouncement), privateKey);

                        res = _forum.read(_publicKey, publicKey, nAnnouncement, signature);
                        verifyAnnouncements(res);

                        break;

                    case 4: // postGeneral
                        System.out.println("Enter the message to be posted:");
                        message = keyboardSc.nextLine();

                        //TODO: get list of announcement's IDs to quote
                        quotedAnnouncements = new ArrayList<>();
                        timestamp = LocalDateTime.now();
                        privateKey = loadPrivateKey(_id);
                        signature = Signing_RSA.sign(_publicKey.toString() + message + quotedAnnouncements.toString() + timestamp.toString(), privateKey);

                        res = _forum.postGeneral(_publicKey, message, quotedAnnouncements, timestamp, signature);
                        verifyResponse(res);

                        break;

                    case 5: // readGeneral
                        System.out.println("Enter the number of announcements:");
                        nAnnouncement = Integer.parseInt(keyboardSc.nextLine());

                        privateKey = loadPrivateKey(_id);
                        signature = Signing_RSA.sign(_publicKey.toString() + Integer.toString(nAnnouncement), privateKey);

                        res = _forum.readGeneral(_publicKey, nAnnouncement, signature);
                        verifyAnnouncements(res);

                        break;

                    case 6: // exit
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
            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
    }

    private static PrivateKey loadPrivateKey(String id) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        return (PrivateKey) keystore.getKey("client" + id, ("client" + id).toCharArray());
    }

    private static PublicKey loadPublicKey(String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableKeyException {

        FileInputStream fis = new FileInputStream("src/main/resources/keystoreclient" + id + ".jks");

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, ("client" + id).toCharArray());
        Certificate cert = keystore.getCertificate("client" + id);
        return cert.getPublicKey();
    }

    private void verifyResponse(Response res) {
        boolean success = Signing_RSA.verify(res.getResponse(), res.getSignature(), _serverKey);

        if(success) {
            System.out.println(res.getResponse());
        }
        else {
            System.out.println("ERROR. SECURITY VIOLATION WAS DETECTED!!");
        }
    }

    private void verifyAnnouncements(Response res) {
        boolean success = Signing_RSA.verify(res.getAnnouncements().toString(), res.getSignature(), _serverKey);

        if(success) {
            // System.out.println(res.getAnnouncements());
            System.out.println("Got " + res.getAnnouncements().size() + " announcements!");
        }
        else {
            System.out.println("ERROR. SECURITY VIOLATION WAS DETECTED!!");
        }
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
