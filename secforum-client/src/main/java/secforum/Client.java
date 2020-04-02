package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client {
    private String _id;
    private PublicKey _publicKey;
    private PublicKey _serverKey;
    private ForumInterface _forum;
    private Scanner _keyboardSc;

    public Client(String id) {
        try {
            _id = id;
            _publicKey = Utils.loadPublicKey(id);
            System.out.println(_publicKey);

            _serverKey = Utils.loadPublicKeyFromCerificate("src/main/resources/server.cer");

            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
        } catch (NotBoundException | NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException e) {
            System.out.println(e.getMessage());
        }

        _keyboardSc = new Scanner(System.in);
    }

    public void start() {
        int command, nAnnouncement;
        String id, message;
        PublicKey publicKey;

        while (true) {
            System.out.println("1 - register\n2 - post\n3 - read\n4 - postGeneral\n5 - readGeneral\n6 - exit");

            try {
                command = Integer.parseInt(_keyboardSc.nextLine());
                List<String> quotedAnnouncements;
                PrivateKey privateKey;
                LocalDateTime timestamp;
                Response res;
                List<Object> toSerialize;
                byte[] signature;
                byte[] messageBytes;
                Integer nonce;
                String password;

                switch (command) {
                    case 1: // register
                        res = _forum.register(_publicKey);

                        res.verify(_serverKey, 0);
                        break;

                    case 2: // post
                        System.out.println("Enter the message to be posted:");
                        message = _keyboardSc.nextLine();

                        quotedAnnouncements = new ArrayList<>();

                        nAnnouncement = requestInt("Enter the number of announcements to be quoted:");

                        for (int i = 0; i < nAnnouncement; i++) {
                            System.out.println("(" + i + 1 + ") Enter the announcement ID:");
                            quotedAnnouncements.add(_keyboardSc.nextLine());
                        }

                        timestamp = LocalDateTime.now();

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);
                        password = null;

                        res = _forum.getNonce(_publicKey);
                        nonce = res.verifyNonce(_publicKey);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(message);
                        toSerialize.add(quotedAnnouncements);
                        toSerialize.add(timestamp);
                        toSerialize.add(nonce);

                        messageBytes = Utils.serializeMessage(toSerialize);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        res = _forum.post(_publicKey, message, quotedAnnouncements, timestamp, signature);

                        res.verify(_serverKey,nonce + 1);
                        break;

                    case 3: // read
                        System.out.println("Enter the id of the client you want to read from:");
                        id = _keyboardSc.nextLine();

                        publicKey = Utils.loadPublicKey(id);

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);
                        password = null;

                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        res = _forum.getNonce(_publicKey);
                        nonce = res.verifyNonce(_publicKey);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(publicKey);
                        toSerialize.add(nAnnouncement);
                        toSerialize.add(nonce);

                        messageBytes = Utils.serializeMessage(toSerialize);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        res = _forum.read(_publicKey, publicKey, nAnnouncement, signature);

                        res.verify(_serverKey,nonce + 1);
                        break;

                    case 4: // postGeneral
                        System.out.println("Enter the message to be posted:");
                        message = _keyboardSc.nextLine();

                        quotedAnnouncements = new ArrayList<>();

                        nAnnouncement = requestInt("Enter the number of announcements to be quoted:");

                        for(int i = 0; i < nAnnouncement; i++) {
                            System.out.println("(" + i + 1 + ") Enter the announcement ID:");
                            quotedAnnouncements.add(_keyboardSc.nextLine());
                        }

                        timestamp = LocalDateTime.now();

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);
                        password = null;

                        res = _forum.getNonce(_publicKey);
                        nonce = res.verifyNonce(_publicKey);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(message);
                        toSerialize.add(quotedAnnouncements);
                        toSerialize.add(timestamp);
                        toSerialize.add(nonce);

                        messageBytes = Utils.serializeMessage(toSerialize);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        res = _forum.postGeneral(_publicKey, message, quotedAnnouncements, timestamp, signature);

                        res.verify(_serverKey,nonce + 1);
                        break;

                    case 5: // readGeneral
                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);
                        password = null;

                        res = _forum.getNonce(_publicKey);
                        nonce = res.verifyNonce(_publicKey);

                        toSerialize = new ArrayList<>();
                        toSerialize.add(_publicKey);
                        toSerialize.add(nAnnouncement);
                        toSerialize.add(nonce);

                        messageBytes = Utils.serializeMessage(toSerialize);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        res = _forum.readGeneral(_publicKey, nAnnouncement, signature);

                        res.verify(_serverKey,nonce + 1);
                        break;

                    case 6: // exit
                        System.out.println("Thank you for using the app");
                        return;

                    default:
                        System.out.println("ERROR. Must be between 1 and 6");
                        break;
                }
            } catch (NumberFormatException e) {
                System.out.println("ERROR. Must be integer.");
            } catch (RemoteException e) {
                System.out.println(e.detail.toString());
            } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException | UnrecoverableKeyException | IllegalArgumentException e) {
                e.printStackTrace();
            }
        }
    }

    private int requestInt(String prompt) throws NumberFormatException {
        int input;
        do {
            System.out.println(prompt);
            input = Integer.parseInt(_keyboardSc.nextLine());
        } while (input < 0);

        return input;
    }

//    private void verifyResponse(Response res, Integer nonce) {
//        List<Object> toSerialize = new ArrayList<>();
//        toSerialize.add(res.getResponse());
//        toSerialize.add(nonce);
//
//        try {
//            byte[] messageBytes = Utils.serializeMessage(toSerialize);
//
//            if(SigningSHA256_RSA.verify(messageBytes, res.getSignature(), _serverKey)) {
//                System.out.println(res.getResponse());
//            }
//            else {
//                System.out.println("ERROR. SECURITY VIOLATION WAS DETECTED!!");
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void verifyAnnouncements(Response res, Integer nonce) {
//        List<Object> toSerialize = new ArrayList<>();
//        toSerialize.add(res.getAnnouncements());
//        toSerialize.add(nonce);
//
//        try {
//            byte[] messageBytes = Utils.serializeMessage(toSerialize);
//
//            if(SigningSHA256_RSA.verify(messageBytes, res.getSignature(), _serverKey)) {
//
//                for(Announcement a : res.getAnnouncements()) {
//                    System.out.println(a);
//                }
//                System.out.println("Got " + res.getAnnouncements().size() + " announcements!\n");
//            }
//            else {
//                System.out.println("ERROR. SECURITY VIOLATION WAS DETECTED!!");
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }

    public static void main(String[] args) {
        Client c = new Client(args[0]);
        c.start();
    }
}
