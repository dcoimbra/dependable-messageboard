package secforum;

import security.HashingSHA256;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Forum extends UnicastRemoteObject implements ForumInterface, ForumReliableBroadcastInterface, Serializable {

    private static final int _f = 1;
    private static final int _N = 3 * _f + 1;
    private final Map<PublicKey, Account> _accounts;
    private final Board _generalBoard;
    private PrivateKey _privKey;
    private final ExceptionResponse _notClient;
    private int _ts;
    private List<ForumReliableBroadcastInterface> _otherServers;
    private final List<EchoMessage> _echos;
    private final List<EchoMessage> _readys;
    private boolean _delivered;
    private int _rank;

    private static final String POST_RESPONSE = "Successfully uploaded the post.";
    private static final String INTERNAL_ERROR = "\nInternal server error! Operation failed!";
    private static final String SECURITY_ERROR = "\nSecurity error! Message was altered!";
    private static final String NEGATIVE_ERROR = "\nRequest error! Number of announcements cannot be negative!";

    /**
     *
     * @throws RemoteException if there is a remote error
     */
    public Forum(String password) throws RemoteException {
        _delivered = false;
        _echos = new ArrayList<>();
        _readys = new ArrayList<>();

        _accounts = new HashMap<>();
        _generalBoard = new Board();

        FileInputStream fis;
        try {
            fis = new FileInputStream("src/main/resources/keystoreserver.jks");
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(fis, (password).toCharArray());
            _privKey = (PrivateKey) keystore.getKey("server", (password).toCharArray());
            _ts = 0;
            _rank = -1;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | IOException e) {
            System.out.println("Could not load private key. SHUTTING DOWN!!!");
            System.exit(0);
        }

        _notClient = new ExceptionResponse(new RemoteException("\nRequest error! User is not registered!"), _privKey, -1, -1);
    }

    public void setOtherServers(List<ForumReliableBroadcastInterface> otherServers) {
        _otherServers = otherServers;
    }

    public Response getNonce(PublicKey pubKey) {
        if(!verifyRegistered(pubKey)){
            return new NonceResponse(_privKey, _accounts.get(pubKey).getNonce());
        }

        return _notClient;
    }

    /**
     *
     * @param pubKey of the user who is registered
     * @return Response positive if successfully registered
     */
    public synchronized Response register(PublicKey pubKey) {
        EchoMessage echoMessage = new EchoMessageRegister(pubKey);

        Response res;

        try {
            echoMessage = (EchoMessageRegister) byzantineReliableBroadcast(echoMessage);
        } catch (InterruptedException | RemoteException e) {
           res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, 0);
        }

        if (_delivered) {
            _delivered = false;
            if (_accounts.putIfAbsent(pubKey, new Account(pubKey)) != null) {
                res = new ExceptionResponse(new RemoteException("\nRequest error! User is already registered!"), _privKey, 0, -1);
            } else {
                 System.out.println("Registered new user successfully.");
                 
                 res = new WriteResponse("Registered successfully.", _privKey, _accounts.get(pubKey).getNonce(), -1);
            }

            try {
                ForumServer.writeForum(this);
            } catch (IOException e) {
                res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, _accounts.get(pubKey).getNonce(), -1);
            }

            _accounts.get(pubKey).setNonce();
            return res;
        }
        res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, -1);
        _accounts.get(pubKey).setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param signature signature of the sender
     */
    public Response post(PublicKey pubKey, String message, List<String> a, int wts, int rank, byte[] signature) {
        EchoMessage echoMessage = new EchoMessagePost(pubKey, message, a, wts);
        
      Account account = _accounts.get(pubKey);
        if (account == null) {
            return _notClient;
        }

        Response res;

        try {
            echoMessage = (EchoMessagePost) byzantineReliableBroadcast(echoMessage);
        } catch (InterruptedException | RemoteException e) {
            res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, account.getNonce());
        }

        if (_delivered) {
            _delivered = false;
            try {
                byte[] messageBytes = Utils.serializeMessage(pubKey, message, a, account.getNonce(), wts, rank);
                if (!SigningSHA256_RSA.verify(messageBytes, signature, pubKey)) {
                    account.setNonce();
                    res = new ExceptionResponse(new RemoteException(SECURITY_ERROR), _privKey, account.getNonce(), wts);
                } else {
                    List<Announcement> announcements = verifyAnnouncements(a);

                    account.post(message, announcements, signature, wts, rank);
                    System.out.println("Someone just posted in their personal board.");

                    for (Map.Entry<ClientCallbackInterface, int[]> listener : account.getListeners().entrySet()) {
                        int number = listener.getValue()[0];
                        int rid = listener.getValue()[1];
                        List<Announcement> writeBackAnnouncements = account.read(number);
                        res = new ReadResponse(writeBackAnnouncements, _privKey, 0, rid);
                        listener.getKey().writeBack(res);
                    }

                    account.setNonce();
                    res = new WriteResponse(POST_RESPONSE, _privKey, account.getNonce(), account.getTs());
                    ForumServer.writeForum(this);
                }
            } catch (RemoteException re) {
                account.setNonce();
                res = new ExceptionResponse(re, _privKey, account.getNonce());
            } catch (IOException e) {
                res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, account.getNonce());
            }

            account.setNonce();
            return res;
        }

        res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, account.getNonce());
        account.setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param requestSignature of the sender
     */
    public synchronized Response postGeneral(PublicKey pubKey, String message, List<String> a, int rid, int ts, int rank, byte[] requestSignature, byte[] announcementSignature) {
        Account account = _accounts.get(pubKey);
        if(account == null) {
            return _notClient;
        }
      
        EchoMessage echoMessage = new EchoMessagePostGeneral(pubKey, message, a, wts);

        Response res;

        try {
            echoMessage = (EchoMessagePostGeneral) byzantineReliableBroadcast(echoMessage);
        } catch (InterruptedException | RemoteException e) {
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, account.getNonce(), rid);
        }

        if (_delivered) {
            _delivered = false;
            if (ts > _ts || (ts == _ts && rank > _rank)) {
                _ts = ts;
                _rank = rank;

                try {
                    byte[] messageBytes = Utils.serializeMessage(pubKey, message, a, account.getNonce(), rid, ts, rank);
                    if (!SigningSHA256_RSA.verify(messageBytes, requestSignature, pubKey)) {
                        account.setNonce();
                        res = new ExceptionResponse(new RemoteException(SECURITY_ERROR), _privKey, account.getNonce(), rid);
                    } else {
                        List<Announcement> announcements = verifyAnnouncements(a);

                        _generalBoard.post(pubKey, message, announcements, account.getNonce(), announcementSignature, account.getCounter(), ts, rank);
                        System.out.println("Someone just posted in the general board.");

                        account.setNonce();
                        res = new WriteResponse(POST_RESPONSE, _privKey, account.getNonce(), rid);
                        ForumServer.writeForum(this);
                    }
                } catch (RemoteException re) {
                    account.setNonce();
                    res = new ExceptionResponse(re, _privKey, account.getNonce(), rid);
                } catch (IOException ioe) {
                    res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, account.getNonce(), rid);
                }

                account.setNonce();
                return res;
            }

            account.setNonce();
            return new ExceptionResponse(new RemoteException("\nRegister error! Request already processed!"), _privKey, account.getNonce(), rid);
        }

        res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, account.getNonce(), rid);
        account.setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user to read from
     * @param number of posts to read
     * @param signature of the sender
     * @return Response read posts
     */
    public Response read(PublicKey senderPubKey, PublicKey pubKey, int number, int rid, Remote clientStub, byte[] signature) {
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        EchoMessage echoMessage = new EchoMessageRead(senderPubKey, pubKey, number, rid, clientStub, signature);

        Response res;
        try {
            echoMessage = (EchoMessageRead) byzantineReliableBroadcast(echoMessage);
        } catch (InterruptedException | RemoteException e) {
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce());
        }

        if (_delivered) {
            _delivered = false;

            Account targetAccount = _accounts.get(pubKey);
            if(targetAccount == null) {
                senderAccount.setNonce();
                res = new ExceptionResponse(new RemoteException("\nRequest error! Target account does not exist!"), _privKey, senderAccount.getNonce(), rid);
            } else if (number < 0) {
                senderAccount.setNonce();
                res = new ExceptionResponse(new RemoteException(NEGATIVE_ERROR), _privKey, senderAccount.getNonce(), rid);
            } else {
                byte[] messageBytes;
                try {
                    messageBytes = Utils.serializeMessage(senderPubKey, pubKey, number, senderAccount.getNonce(), rid, clientStub);
                } catch (IllegalArgumentException e) {
                    senderAccount.setNonce();
                    res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid)
                    senderAccount.setNonce();
                    return res;
                }

                try {
                    if (!SigningSHA256_RSA.verify(messageBytes, signature, senderPubKey)) {
                        senderAccount.setNonce();
                        res = new ExceptionResponse(new RemoteException(SECURITY_ERROR), _privKey, senderAccount.getNonce(), rid);
                    } else {
                        senderAccount.setNonce();
                        List<Announcement> list = targetAccount.read(number, rid, (ClientCallbackInterface) clientStub);
                        System.out.println("Reading " + list.size() + " posts from a personal board");

                        res = new ReadResponse(list, _privKey, senderAccount.getNonce(), rid);
                        ForumServer.writeForum(this);
                    }
                } catch (RemoteException re) {
                    res = new ExceptionResponse(re, _privKey, senderAccount.getNonce(), rid);
                } catch (IOException e) {
                    res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
                }
            }

            senderAccount.setNonce();
            return res;
        }
        res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
        senderAccount.setNonce();
        return res;
    }

    /**
     *
     * @param number of posts to read
     * @param signature of the sender
     * @return read posts
     */
    public Response readGeneral(PublicKey senderPubKey, int number, int rid, byte[] signature) {
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        EchoMessage echoMessage = new EchoMessageReadGeneral(senderPubKey, number, rid);

        Response res;

        try {
            echoMessage = (EchoMessageReadGeneral) byzantineReliableBroadcast(echoMessage);
        } catch (InterruptedException | RemoteException e) {
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
        }

        if(_delivered) {
             _delivered = false;

            if(number < 0) {
                senderAccount.setNonce();
                res = new ExceptionResponse(new RemoteException(NEGATIVE_ERROR), _privKey, senderAccount.getNonce(), rid);
            } else {
                byte[] messageBytes;
                try {
                    messageBytes = Utils.serializeMessage(senderPubKey, number, _accounts.get(senderPubKey).getNonce(), rid);
                } catch (IllegalArgumentException e) {
                    senderAccount.setNonce();
                    res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
                    senderAccount.setNonce();
                    return res;
                }

                try {
                    if (!SigningSHA256_RSA.verify(messageBytes, signature, senderPubKey)) {
                        senderAccount.setNonce();
                        res = new ExceptionResponse(new RemoteException(SECURITY_ERROR), _privKey, senderAccount.getNonce(), rid);
                    } else {
                        senderAccount.setNonce();
                        List<Announcement> list = _generalBoard.read(number);
                        System.out.println("Reading " + list.size() + " posts from the general board");

                        res = new ReadResponse(list, _privKey, senderAccount.getNonce(), rid);
                        ForumServer.writeForum(this);
                    }
                } catch (RemoteException re) {
                    res = new ExceptionResponse(re, _privKey, senderAccount.getNonce(), rid);
                } catch (IOException e) {
                    res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
                }
            }
            senderAccount.setNonce();
            return res;
        }
        res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
        senderAccount.setNonce();
        return res;
    }

    public Response readComplete(PublicKey pubKey, Remote clientStub, int rid, byte[] signature) {
        Account senderAccount = _accounts.get(pubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        Response res;

        byte[] messageBytes;
        try {
            messageBytes = Utils.serializeMessage(pubKey, clientStub, _accounts.get(pubKey).getNonce(), rid);
        } catch (IllegalArgumentException e) {
            senderAccount.setNonce();
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);

            senderAccount.setNonce();
            return res;
        }

        try {
            if (!SigningSHA256_RSA.verify(messageBytes, signature, pubKey)) {
                senderAccount.setNonce();
                res = new ExceptionResponse(new RemoteException(SECURITY_ERROR), _privKey, senderAccount.getNonce(), rid);
            } else {
                senderAccount.removeListener((ClientCallbackInterface) clientStub);
                res = new WriteResponse("Removed from listeners.", _privKey, senderAccount.getNonce(), _ts);
                ForumServer.writeForum(this);
            }
        } catch (IOException e) {
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
        }

        senderAccount.setNonce();
        return res;
    }

    protected PublicKey loadPublicKey() {
        try {
            FileInputStream fis = new FileInputStream("src/main/resources/keystoreserver.jks");
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(fis, ("server").toCharArray());
            Certificate cert = keystore.getCertificate("server");
            return cert.getPublicKey();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verifyRegistered(PublicKey pubKey) {
        return !_accounts.containsKey(pubKey);
    }

    private List<Announcement> verifyAnnouncements(List<String> announcementIDs) throws RemoteException {
        List<Announcement> announcements = new ArrayList<>();

        for(String id : announcementIDs) {
            Announcement announcement = announcementExists(id);

            if(announcement == null) {
                throw new RemoteException("\n Request error! Announcement " + id + " does not exist!");
            }
            else {
                announcements.add(announcement);
            }
        }
        return announcements;
    }

    private Announcement announcementExists(String id) throws IllegalArgumentException {
        for(Map.Entry<PublicKey, Account> entry : _accounts.entrySet()) {
            for(Announcement announcement : entry.getValue().getBoardAnnouncements()) {
                if(HashingSHA256.equals(id, announcement.getId())) {
                    return announcement;
                }
            }
        }

        for(Announcement announcement : _generalBoard.getAnnouncements()) {
            if(HashingSHA256.equals(id, announcement.getId())) {
                return announcement;
            }
        }

        return null;
    }


    private EchoMessage compareMessages(List<EchoMessage> messages) {

        System.out.println("Comparing messages...");
        EchoMessage message;
        int quorumCounter = 0;

        for (int i = 0; i < messages.size(); i++) {
            message = messages.get(i);

            for (int j = 0; j < messages.size(); j++) {
                if (i != j) {
                    EchoMessage other = messages.get(j);
                    if (other.equals(message)) {
                        quorumCounter++;

                        if (quorumCounter > (_N * _f) / 2) {
                            System.out.println("Got a quorum.");
                            return message;
                        }
                    }
                }
            }
        }

        return null;
    }


    public EchoMessage byzantineReliableBroadcast(EchoMessage message) throws InterruptedException, RemoteException {
        List<Thread> threads = new ArrayList<>();

        System.out.println("Echo.");
        for (int i = 0; i < _N - 1; i++) {
            threads.add(new Thread(new EchoRequest(message, _otherServers.get(i))));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join();
            System.out.println("Thread joined.");
        }

        System.out.println("Waiting for echo quorum...");
        while ((_echos.size() <= (_N + _f) / 2)) {
            System.out.println(_echos.size());
        }

        EchoMessage echoMessage = compareMessages(_echos);

        if (echoMessage == null) {
            System.out.println("No echo quorum.");
            throw new RemoteException("No echo quorum");
        }

        System.out.println("Echo quorum. Ready.");

        threads = new ArrayList<>();

        for (int i = 0; i < _N - 1; i++) {
            threads.add(new Thread(new ReadyRequest(echoMessage, _otherServers.get(i))));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join();
            System.out.println("Thread joined.");
        }

        System.out.println("Waiting for ready quorum...");
        while ((_readys.size() <= 2 * _f)) {
            System.out.println(_readys.size());
        }

        EchoMessage readyMessage = compareMessages(_readys);

        if (readyMessage == null) {
            System.out.println("No ready quorum.");
            throw new RemoteException("No ready quorum.");
        }

        System.out.println("Ready quorum. Delivering message.");
        _delivered = true;
        message = readyMessage;

        _echos.clear();
        _readys.clear();

        return message;
    }


    @Override
    public void echo(EchoMessage message) {
        System.out.println("Got an echo.");
        _echos.add(message);
    }

    @Override
    public void ready(EchoMessage message) {
        System.out.println("Someone is ready.");
        _readys.add(message);
    }
}
