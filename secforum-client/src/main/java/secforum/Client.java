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
    private String _id;
    private PublicKey _publicKey;
    private PublicKey _serverKey;
    private List<ForumInterface> _forums = new ArrayList<>();
    private Scanner _keyboardSc;

    public Client(String id) {
        try {
            _id = id;
            _publicKey = Utils.loadPublicKey(id);
            _serverKey = Utils.loadPublicKeyFromCerificate("src/main/resources/server.cer");

            String name;
            for (int i = 0; i <= 3; i++) {
                name = "//localhost:" + (1099 + i) + "/forum" + i;
                _forums.add((ForumInterface) Naming.lookup(name));
                System.out.println("Found server: " + name);
            }

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
                Response res;
                byte[] signature;
                byte[] messageBytes;
                String password;
                Integer nonce = 0;

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

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, message, quotedAnnouncements, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.post(_publicKey, message, quotedAnnouncements, signature);
                            System.out.println("Verifying post");
                            res.verify(_serverKey, nonce + 1);
                        }
                        break;

                    case 3: // read
                        System.out.println("Enter the id of the client you want to read from:");
                        id = _keyboardSc.nextLine();

                        publicKey = Utils.loadPublicKey(id);

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);

                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, publicKey, nAnnouncement, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.read(_publicKey, publicKey, nAnnouncement, signature);
                            res.verify(_serverKey, nonce + 1);
                        }
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

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, message, quotedAnnouncements, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.postGeneral(_publicKey, message, quotedAnnouncements, signature);
                            res.verify(_serverKey, nonce + 1);
                        }
                        break;

                    case 5: // readGeneral
                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        System.out.println("Enter your private key password:");
                        password = _keyboardSc.nextLine();
                        privateKey = Utils.loadPrivateKey(_id, password);

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);
                        }

                        messageBytes = Utils.serializeMessage(_publicKey, nAnnouncement, nonce);
                        signature = SigningSHA256_RSA.sign(messageBytes, privateKey);

                        for (ForumInterface forum : _forums) {
                            res = forum.readGeneral(_publicKey, nAnnouncement, signature);
                            res.verify(_serverKey, nonce + 1);
                        }
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
                System.out.println(e.getMessage());
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

    public static void main(String[] args) {
        Client c = new Client(args[0]);
        c.start();
    }
}
