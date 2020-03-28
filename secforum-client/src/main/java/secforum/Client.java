package secforum;

import security.Signing_RSA;
import security.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
            _publicKey = Utils.loadPublicKey(id);
            System.out.println(_publicKey.getEncoded());

            FileInputStream fin = new FileInputStream("src/main/resources/server.cer");
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
            _serverKey = certificate.getPublicKey();

            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
        } catch (RemoteException | NotBoundException | MalformedURLException e) {
            System.out.println(e.getMessage());
        } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException e) {
            e.printStackTrace();
        }

        keyboardSc = new Scanner(System.in);
    }

    public void start() {
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
                List<Object> toSerialize;
                byte[] signature;
                byte[] messageBytes;

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
                        privateKey = Utils.loadPrivateKey(_id);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(message);
                        toSerialize.add(quotedAnnouncements);
                        toSerialize.add(timestamp);

                        messageBytes = Utils.serializeMessage(toSerialize);

                        signature = Signing_RSA.sign(messageBytes, privateKey);

                        res = _forum.post(_publicKey, message, quotedAnnouncements, timestamp, signature);
                        verifyResponse(res);

                        break;

                    case 3: // read
                        System.out.println("Enter client id:");
                        id = keyboardSc.nextLine();

                        publicKey = Utils.loadPublicKey(id);
                        privateKey = Utils.loadPrivateKey(_id);
                        System.out.println("Enter the number of announcements:");
                        nAnnouncement = Integer.parseInt(keyboardSc.nextLine());

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(publicKey);
                        toSerialize.add(nAnnouncement);
                        messageBytes = Utils.serializeMessage(toSerialize);

                        signature = Signing_RSA.sign(messageBytes, privateKey);

                        res = _forum.read(_publicKey, publicKey, nAnnouncement, signature);
                        verifyAnnouncements(res);

                        break;

                    case 4: // postGeneral
                        System.out.println("Enter the message to be posted:");
                        message = keyboardSc.nextLine();

                        //TODO: get list of announcement's IDs to quote
                        quotedAnnouncements = new ArrayList<>();
                        timestamp = LocalDateTime.now();
                        privateKey = Utils.loadPrivateKey(_id);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(message);
                        toSerialize.add(quotedAnnouncements);
                        toSerialize.add(timestamp);
                        messageBytes = Utils.serializeMessage(toSerialize);

                        signature = Signing_RSA.sign(messageBytes, privateKey);

                        res = _forum.postGeneral(_publicKey, message, quotedAnnouncements, timestamp, signature);
                        verifyResponse(res);

                        break;

                    case 5: // readGeneral
                        System.out.println("Enter the number of announcements:");
                        nAnnouncement = Integer.parseInt(keyboardSc.nextLine());

                        privateKey = Utils.loadPrivateKey(_id);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(nAnnouncement);
                        messageBytes = Utils.serializeMessage(toSerialize);

                        signature = Signing_RSA.sign(messageBytes, privateKey);

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
            } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
    }

    private void verifyResponse(Response res) {
        boolean success = Signing_RSA.verify(Utils.serialize(res.getResponse()), res.getSignature(), _serverKey);

        if(success) {
            System.out.println(res.getResponse());
        }
        else {
            System.out.println("ERROR. SECURITY VIOLATION WAS DETECTED!!");
        }
    }

    private void verifyAnnouncements(Response res) {
        boolean success = Signing_RSA.verify(Utils.serialize(res.getAnnouncements()), res.getSignature(), _serverKey);

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
        c.start();
    }
}
