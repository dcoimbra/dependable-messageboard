package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client {
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private PublicKey _serverKey;
    private List<ForumInterface> _forums = new ArrayList<>();
    private Scanner _keyboardSc;
    private static final int _f = 1;
    private static final int _N = 3 * _f + 1;

    public Client(String id) {
        try {
            _keyboardSc = new Scanner(System.in);

            _publicKey = Utils.loadPublicKey(id);
            _serverKey = Utils.loadPublicKeyFromCerificate("src/main/resources/server.cer");

            System.out.println("Enter your private key password:");
            String password = _keyboardSc.nextLine();
            _privateKey = Utils.loadPrivateKey(id, password);

            String name;
            for (int i = 0; i < _N; i++) {
                name = "//localhost:" + (1099 + i) + "/forum" + i;
                _forums.add((ForumInterface) Naming.lookup(name));
                System.out.println("Found server: " + name);
            }

        } catch (NotBoundException | NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
            System.out.println(e.getMessage());
        }
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
                Response res;
                List<Response> resList = new ArrayList<>();
                List<Response> readlist = new ArrayList<>();
                byte[] signature;
                byte[] messageBytes;
                Integer nonce = 0;
                int acks = 0;

                switch (command) {
                    case 1: // register
                        for (ForumInterface forum : _forums) {
                            res = forum.register(_publicKey);
                            res.verify(_serverKey, 0);
                        }
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

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, message, quotedAnnouncements, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.post(_publicKey, message, quotedAnnouncements, signature);
                            resList.add(res);
                        }

                        System.out.println("Verifying post");

                        for (Response r : resList) {
                            try {
                                if (r.verify(_serverKey, nonce + 1)) {
                                    acks++;
                                }
                            } catch (IllegalArgumentException e) {
                                System.out.println(e.getMessage());
                                System.out.println("Not acknowledged. Carrying on...");
                            }
                        }

                        if (acks > (_N + _f) / 2) {
                            System.out.println("Post verified.");
                        }

                        else {
                            throw new IllegalArgumentException("ERROR: Byzantine fault detected.");
                        }

                        break;

                    case 3: // read
                        System.out.println("Enter the id of the client you want to read from:");
                        id = _keyboardSc.nextLine();

                        publicKey = Utils.loadPublicKey(id);

                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, publicKey, nAnnouncement, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.read(_publicKey, publicKey, nAnnouncement, signature);
                            resList.add(res);
                        }

                        verifyRead(resList, readlist, nonce);
                        printAnnouncements(readlist);

                        break;

                    case 4: // postGeneral
                        System.out.println("Enter the message to be posted:");
                        message = _keyboardSc.nextLine();

                        quotedAnnouncements = new ArrayList<>();

                        nAnnouncement = requestInt("Enter the number of announcements to be quoted:");

                        for (int i = 0; i < nAnnouncement; i++) {
                            System.out.println("(" + i + 1 + ") Enter the announcement ID:");
                            quotedAnnouncements.add(_keyboardSc.nextLine());
                        }

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, message, quotedAnnouncements, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.postGeneral(_publicKey, message, quotedAnnouncements, signature);
                            resList.add(res);
                        }

                        System.out.println("Verifying post");

                        for (Response r : resList) {
                            try {
                                if (r.verify(_serverKey, nonce + 1)) {
                                    acks++;
                                }
                            } catch (IllegalArgumentException e) {
                                System.out.println(e.getMessage());
                                System.out.println("Not acknowledged. Carrying on...");
                            }
                        }

                        if (acks > (_N + _f) / 2) {
                            System.out.println("Post verified.");
                        }

                        else {
                            throw new IllegalArgumentException("ERROR: Byzantine fault detected.");
                        }

                        break;

                    case 5: // readGeneral
                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, nAnnouncement, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.readGeneral(_publicKey, nAnnouncement, signature);
                            resList.add(res);
                        }

                        verifyRead(resList, readlist, nonce);
                        printAnnouncements(readlist);

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
            } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException | IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private void verifyRead(List<Response> resList, List<Response> readlist, Integer nonce) {
        for (Response r : resList) {
            try {
                if (r.verify(_serverKey, nonce + 1)) {
                    readlist.add(r);
                }
            } catch (IllegalArgumentException e) {
                System.out.println(e.getMessage());
                System.out.println("Signature mismatch. Carrying on...");
            }
        }
    }


    private void printAnnouncements(List<Response> readlist) throws IllegalArgumentException {
        if (readlist.size() > (_N + _f) / 2) {
            Response v = highestRes(readlist);

            List<Announcement> announcements = v.getAnnouncements();

            for (Announcement a : announcements) {
                System.out.println(a);
            }
            System.out.println("Got " + announcements.size() + " announcements!\n");
        }

        else {
            throw new IllegalArgumentException("ERROR: Byzantine fault detected.");
        }
    }

    private Response highestRes(List<Response> readlist) {
        int highestNonce = 0;
        Response highestResponse = null;
        for (Response res : readlist) {
            Announcement mostRecentAnnouncement = res.getAnnouncements().get(0);
            Integer nonce = mostRecentAnnouncement.getNonce();

            if (nonce >= highestNonce) {
                highestNonce = nonce;
                highestResponse = res;
            }
        }

        return highestResponse;
    }

    private int requestInt(String prompt) throws NumberFormatException {
        int input;
        do {
            System.out.println(prompt);
            input = Integer.parseInt(_keyboardSc.nextLine());
        } while (input < 0);

        return input;
    }

    public static void main(String[] args) {
        Client c = new Client(args[0]);
        c.start();
    }
}
