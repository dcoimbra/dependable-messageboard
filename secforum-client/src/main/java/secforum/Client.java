package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client implements ClientCallbackInterface {
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private PublicKey _serverKey;
    private List<ForumInterface> _forums = new ArrayList<>();
    private Scanner _keyboardSc;
    private Remote _clientStub;
    private static final int _f = 1;
    private static final int _N = 3 * _f + 1;
    private static ByzantineRegularRegister _regularRegister;
    private static ByzantineRegularRegister _regularRegisterGeneral;

    public Client(String id) {

        try {
            _clientStub = UnicastRemoteObject.exportObject(this, 8887 + Integer.parseInt(id));
            _keyboardSc = new Scanner(System.in);

            _publicKey = Utils.loadPublicKey(id);
            _serverKey = Utils.loadPublicKeyFromCerificate("src/main/resources/server.cer");

            System.out.println("Enter your private key password:");
            String password = _keyboardSc.nextLine();
            _privateKey = Utils.loadPrivateKey(id, password);
            _regularRegister = new ByzantineRegularRegister();
            _regularRegisterGeneral = new ByzantineRegularRegister();

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
                List<Response> readlist;
                byte[] signature;
                byte[] messageBytes;
                Integer nonce;
                int wts;
                int rid;

                switch (command) {
                    case 1: // register
                        for (ForumInterface forum : _forums) {
                            res = forum.register(_publicKey);
                            res.verify(_serverKey, 0, 0);
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

                        _regularRegister.setWts();
                        wts = _regularRegister.getWts();
                        _regularRegister.clearAcklist();

                        for(ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);

                            messageBytes = Utils.serializeMessage(_publicKey, message, quotedAnnouncements, nonce, wts);
                            signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                            res = forum.post(_publicKey, message, quotedAnnouncements, wts, signature);

                            try {
                                if(res.verify(_serverKey, nonce + 1, wts)) {
                                    _regularRegister.setAcklistValue();
                                }
                            } catch (IllegalArgumentException e) {
                                System.out.println(e.getMessage());
                                System.out.println("Not acknowledged. Carrying on...");
                            }
                        }

                        System.out.println("Verifying post....");

                        if (_regularRegister.getAcklist().size() > (_N + _f) / 2) {
                            System.out.println("Post verified.");
                        } else {
                            throw new IllegalArgumentException("ERROR: Byzantine fault detected.");
                        }

                        break;

                    case 3: // read
                        System.out.println("Enter the id of the client you want to read from:");
                        id = _keyboardSc.nextLine();

                        publicKey = Utils.loadPublicKey(id);

                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        _regularRegister.setRid();
                        rid = _regularRegister.getRid();
                        _regularRegister.clearReadlist();

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);

                            messageBytes = Utils.serializeMessage(_publicKey, publicKey, nAnnouncement, nonce, rid, _clientStub);
                            signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                            res = forum.read(_publicKey, publicKey, nAnnouncement, rid, _clientStub, signature);

                            try {
                                if(res.verify(_serverKey, publicKey, nonce + 1, rid)) {
                                    _regularRegister.setReadlist(res);
                                }
                            } catch (IllegalArgumentException e) {
                                System.out.println(e.getMessage());
                                System.out.println("Not acknowledged. Carrying on...");
                            }
                        }

                        readlist = _regularRegister.getReadlist();
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

                        _regularRegisterGeneral.setWts();
                        wts = _regularRegisterGeneral.getWts();
                        _regularRegisterGeneral.clearAcklist();

                        for(ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);

                            messageBytes = Utils.serializeMessage(_publicKey, message, quotedAnnouncements, nonce, wts);
                            signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

                            res = forum.postGeneral(_publicKey, message, quotedAnnouncements, wts, signature);

                            try {
                                if(res.verify(_serverKey, nonce + 1, wts)) {
                                    _regularRegisterGeneral.setAcklistValue();
                                }
                            } catch (IllegalArgumentException e) {
                                System.out.println(e.getMessage());
                                System.out.println("Not acknowledged. Carrying on...");
                            }
                        }

                        System.out.println("Verifying post....");

                        if (_regularRegisterGeneral.getAcklist().size() > (_N + _f) / 2) {
                            System.out.println("Post verified.");
                        } else {
                            throw new IllegalArgumentException("ERROR: Byzantine fault detected.");
                        }

                        break;

                    case 5: // readGeneral
                        nAnnouncement = requestInt("Enter the number of announcements to read:");

                        _regularRegister.setRid();
                        rid = _regularRegister.getRid();
                        _regularRegister.clearReadlist();

                        for (ForumInterface forum : _forums) {
                            res = forum.getNonce(_publicKey);
                            nonce = res.verifyNonce(_serverKey);

                            messageBytes = Utils.serializeMessage(_publicKey, nAnnouncement, nonce, rid);
                            signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);


                            res = forum.readGeneral(_publicKey, nAnnouncement, rid, signature);

                            try {
                                if(res.verify(_serverKey, _publicKey, nonce + 1, rid)) {
                                    _regularRegister.setReadlist(res);
                                }
                            } catch (IllegalArgumentException e) {
                                System.out.println(e.getMessage());
                                System.out.println("Not acknowledged. Carrying on...");
                            }
                        }

                        readlist = _regularRegister.getReadlist();
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

    @Override
    public void writeBack(List<Announcement> writeBackAnnouncements, int rid) {
        System.out.println("Server contacted me with " + writeBackAnnouncements.size() + " announcements" + " with rid " + rid + ".");
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
        int highestTs = 0;
        Response highestResponse = null;
        for (Response res : readlist) {
            Announcement mostRecentAnnouncement = res.getAnnouncements().get(0);
            int ts = mostRecentAnnouncement.getTs();

            if (ts >= highestTs) {
                highestTs = ts;
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
