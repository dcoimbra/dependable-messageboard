package secforum;

import secforum.response.*;
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
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class Forum extends UnicastRemoteObject implements ForumInterface, ForumReliableBroadcastInterface, Serializable {

    private final Map<PublicKey, Account> _accounts;
    private final Board _generalBoard;
    private PrivateKey _privKey;
    private final ExceptionResponse _notClient;

    private static final int _f = 1;
    private static final int _N = 3 * _f + 1;
    private int _ts;
    private int _rank;
    private final int _id;

    private List<ForumReliableBroadcastInterface> _otherServers;
    private final List<EchoMessage> _echos;
    private transient CountDownLatch _echoLatch = new CountDownLatch(3);
    private final List<EchoMessage> _readys;
    private transient CountDownLatch _readyLatch = new CountDownLatch(3);

    private static final String POST_RESPONSE = "Successfully uploaded the post.";
    private static final String INTERNAL_ERROR = "\nInternal server error! Operation failed!";
    private static final String SECURITY_ERROR = "\nSecurity error! Message was altered!";
    private static final String NEGATIVE_ERROR = "\nRequest error! Number of announcements cannot be negative!";

    /**
     *
     * @throws RemoteException if there is a remote error
     */
    public Forum(String password, int id) throws RemoteException {
        _echos = new Vector<>();
        _readys = new Vector<>();
        _id = id;
        _accounts = new HashMap<>();
        _generalBoard = new Board();

        try {
            _privKey = Utils.loadPrivateKeyServer(Integer.toString(_id), password + _id);
            _ts = 0;
            _rank = -1;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException |
                IOException e) {
            System.out.println("Could not load private key. SHUTTING DOWN!!!");
            System.exit(0);
        }

        _notClient = new ExceptionResponse(new RemoteException("\nRequest error! User is not registered!"), _privKey,
                -1, -1);
    }

    public void setOtherServers(List<ForumReliableBroadcastInterface> otherServers) {
        _otherServers = otherServers;
    }

    public Response switchOp(EchoMessage delivered) throws IllegalArgumentException {
        switch (delivered.getOp()) {
            case "register":
                EchoMessageRegister registerMessage = (EchoMessageRegister) delivered;
                return doRegister(registerMessage.getPubKey());

            case "post":
                EchoMessagePost postMessage = (EchoMessagePost) delivered;
                return doPost(postMessage.getPubKey(), postMessage.getMessage(), postMessage.getQuotedAnnouncements(),
                        postMessage.getWts(), postMessage.getRank(), postMessage.getRequestSignature());

            case "postGeneral":
                EchoMessagePostGeneral postGeneralMessage = (EchoMessagePostGeneral) delivered;
                return doPostGeneral(postGeneralMessage.getPubKey(), postGeneralMessage.getMessage(),
                        postGeneralMessage.getQuotedAnnouncements(), postGeneralMessage.getRid(),
                        postGeneralMessage.getWts(), postGeneralMessage.getRank(),
                        postGeneralMessage.getRequestSignature(), postGeneralMessage.getAnnouncementSignature());

            case "read":
                EchoMessageRead readMessage = (EchoMessageRead) delivered;
                return doRead(readMessage.getPubKey(), readMessage.getTargetKey(), readMessage.getNumber(),
                        readMessage.getRid(), readMessage.getClientStub(), readMessage.getRequestSignature());

            case "readGeneral":
                EchoMessageReadGeneral readGeneralMessage = (EchoMessageReadGeneral) delivered;
                return doReadGeneral(readGeneralMessage.getPubKey(), readGeneralMessage.getNumber(),
                        readGeneralMessage.getRid(), readGeneralMessage.getRequestSignature());

            case "readComplete":
                EchoMessageReadComplete readCompleteMessage = (EchoMessageReadComplete) delivered;
                return doReadComplete(readCompleteMessage.getPubKey(), readCompleteMessage.getClientStub(),
                        readCompleteMessage.getRid(), readCompleteMessage.getRequestSignature());

            default:
                throw new IllegalArgumentException("Unknown operation.");
        }
    }

    private Response broadcastAndExecute(int id, Account senderAccount, EchoMessage echoMessage) {
        EchoMessage delivered = senderAccount.byzantineReliableBroadcast(echoMessage, _otherServers);

        if(delivered != null) {
            return switchOp(delivered);
        }

        Response res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), id);
        senderAccount.setNonce();
        return res;
    }

    public Response getNonce(PublicKey pubKey) {
        System.out.println("====== GETNONCE ======");
        if (verifyRegistered(pubKey)){
            return new NonceResponse(_privKey, _accounts.get(pubKey).getNonce());
        }

        return _notClient;
    }

    public Response getTs(PublicKey pubKey) {
        System.out.println("====== GETTS ======");
        if (verifyRegistered(pubKey)){
            return new NonceResponse(_privKey, _accounts.get(pubKey).getTs());
        }

        return _notClient;
    }

    /**
     *
     * @param pubKey of the user who is registered
     * @return Response positive if successfully registered
     */
    public synchronized Response register(PublicKey pubKey) {
        System.out.println("====== REGISTER ======");

        EchoMessage echoMessage = new EchoMessageRegister(_id, pubKey, _privKey);

        try {
            EchoMessage delivered = byzantineReliableBroadcast(echoMessage);
            return switchOp(delivered);
        } catch (InterruptedException | RemoteException e) {
            return new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, 0,-1);
        }
    }

    public Response doRegister(PublicKey pubKey) {
        Response res;

        if (_accounts.putIfAbsent(pubKey, new Account(pubKey, _id, _privKey)) != null) {
            res = new ExceptionResponse(new RemoteException("\nRequest error! User is already registered!"), _privKey,
                    0, -1);
        } else {
            System.out.println("Registered new user successfully.");

            _accounts.get(pubKey).incMyBroadcastNonce();

            res = new WriteResponse("Registered successfully.", _privKey, _accounts.get(pubKey).getNonce(),
                    -1);
        }

        try {
            ForumServer.writeForum(this);
        } catch (IOException e) {
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, _accounts.get(pubKey).getNonce(),
                    -1);
        }

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
        System.out.println("====== POST ======");
        Account account = _accounts.get(pubKey);
            if (account == null) {
                return _notClient;
            }

        EchoMessage echoMessage = new EchoMessagePost(_id, pubKey, message, a, wts, rank, signature, _privKey,
                account.getMyBroadcastNonce());

        return broadcastAndExecute(wts, account, echoMessage);
    }

    public Response doPost(PublicKey pubKey, String message, List<String> a, int wts, int rank, byte[] signature) {
        Account account = _accounts.get(pubKey);
        if (account == null) {
            return _notClient;
        }

        Response res;

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
            res = new ExceptionResponse(re, _privKey, account.getNonce(), wts);
        } catch (IOException e) {
            res = new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, account.getNonce(), wts);
        }

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
    public synchronized Response postGeneral(PublicKey pubKey, String message, List<String> a, int rid, int ts,
                                             int rank, byte[] requestSignature, byte[] announcementSignature) {
        System.out.println("====== POSTGENERAL ======");

        Account account = _accounts.get(pubKey);
        if(account == null) {
            return _notClient;
        }

        EchoMessage echoMessage = new EchoMessagePostGeneral(_id, pubKey, message, a, rid, ts, rank, requestSignature,
                announcementSignature, _privKey, account.getMyBroadcastNonce());

        return broadcastAndExecute(rid, account, echoMessage);
    }

    public Response doPostGeneral(PublicKey pubKey, String message, List<String> a, int rid, int ts,
                                  int rank, byte[] requestSignature, byte[] announcementSignature) {
        Account account = _accounts.get(pubKey);
        if(account == null) {
            return _notClient;
        }

        Response res;

        if (ts == _ts + 1 || (ts == _ts && rank > _rank)) {
            try {
                byte[] messageBytes = Utils.serializeMessage(pubKey, message, a, account.getNonce(), rid, ts, rank);
                if (!SigningSHA256_RSA.verify(messageBytes, requestSignature, pubKey)) {
                    account.setNonce();
                    res = new ExceptionResponse(new RemoteException(SECURITY_ERROR), _privKey, account.getNonce(), rid);
                } else {
                    List<Announcement> announcements = verifyAnnouncements(a);

                    _generalBoard.post(pubKey, message, announcements, account.getNonce(), announcementSignature, account.getCounter(), ts, rank);
                    System.out.println("Someone just posted in the general board.");

                    _ts = ts;
                    _rank = rank;
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

    /**
     *
     * @param pubKey of the user to read from
     * @param number of posts to read
     * @param signature of the sender
     * @return Response read posts
     */
    public Response read(PublicKey senderPubKey, PublicKey pubKey, int number, int rid, Remote clientStub, byte[] signature) {
        System.out.println("====== READ ======");
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        EchoMessage echoMessage = new EchoMessageRead(_id, senderPubKey, pubKey, number, rid, clientStub, signature,
                _privKey, senderAccount.getMyBroadcastNonce());

        return broadcastAndExecute(rid, senderAccount, echoMessage);
    }

    public Response doRead(PublicKey senderPubKey, PublicKey pubKey, int number, int rid, Remote clientStub, byte[] signature) {
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        Response res;

        Account targetAccount = _accounts.get(pubKey);
        if (targetAccount == null) {
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

    /**
     *
     * @param number of posts to read
     * @param signature of the sender
     * @return read posts
     */
    public Response readGeneral(PublicKey senderPubKey, int number, int rid, byte[] signature) {
        System.out.println("====== READGENERAL ======");
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        EchoMessage echoMessage = new EchoMessageReadGeneral(_id, senderPubKey, number, rid, signature, _privKey,
                senderAccount.getMyBroadcastNonce());

        return broadcastAndExecute(rid, senderAccount, echoMessage);
    }

    public Response doReadGeneral(PublicKey senderPubKey, int number, int rid, byte[] signature) {
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        Response res;

        if (number < 0) {
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

    public Response readComplete(PublicKey pubKey, Remote clientStub, int rid, byte[] signature) {
        System.out.println("====== READCOMPLETE ======");
        Account senderAccount = _accounts.get(pubKey);
        if(senderAccount == null) {
            return null;
        }

        EchoMessage echoMessage = new EchoMessageReadComplete(_id, pubKey, clientStub, rid, signature, _privKey,
                senderAccount.getMyBroadcastNonce());

        return broadcastAndExecute(rid, senderAccount, echoMessage);
    }

    public Response doReadComplete(PublicKey pubKey, Remote clientStub, int rid, byte[] signature) {
        Account senderAccount = _accounts.get(pubKey);
        if(senderAccount == null) {
            return null;
        }

        byte[] messageBytes;
        try {
            messageBytes = Utils.serializeMessage(pubKey, clientStub, _accounts.get(pubKey).getNonce(), rid);
        } catch (IllegalArgumentException e) {
            senderAccount.setNonce();

            senderAccount.setNonce();
            return null;
        }

        try {
            if (!SigningSHA256_RSA.verify(messageBytes, signature, pubKey)) {
                senderAccount.setNonce();
            } else {
                System.out.println("Removing listener");
                senderAccount.removeListener((ClientCallbackInterface) clientStub);
                ForumServer.writeForum(this);
            }
        } catch (IOException e) {
            return new ExceptionResponse(new RemoteException(INTERNAL_ERROR), _privKey, senderAccount.getNonce(), rid);
        }

        senderAccount.setNonce();
        return null;
    }

    public static PublicKey loadPublicKey(int id) {
        try {
            FileInputStream fis = new FileInputStream("src/main/resources/keystoreserver" + id + ".jks");
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(fis, ("server" + id).toCharArray());
            Certificate cert = keystore.getCertificate("server" + id);
            return cert.getPublicKey();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            return null;
        }
    }

    private boolean verifyRegistered(PublicKey pubKey) {
        return _accounts.containsKey(pubKey);
    }

    private List<Announcement> verifyAnnouncements(List<String> announcementIDs) throws RemoteException {
        List<Announcement> announcements = new ArrayList<>();

        for(String id : announcementIDs) {
            Announcement announcement = announcementExists(id);

            if(announcement == null) {
                throw new RemoteException("\nRequest error! Announcement " + id + " does not exist!");
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


    public static EchoMessage compareMessages(List<EchoMessage> messages) {

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

                        if (quorumCounter > (_N + _f) / 2) {
                            System.out.println("Got a quorum.");
                            return message;
                        }
                    }
                }
            }
        }

        return null;
    }
    
    private EchoMessage byzantineReliableBroadcast(EchoMessage message) throws InterruptedException, RemoteException {

        List<Thread> threads = new ArrayList<>();

        System.out.println("Echo.");
        for (int i = 0; i < _N - 1; i++) {
            threads.add(new Thread(new EchoRequest(message, _otherServers.get(i))));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join();
        }

        System.out.println("Waiting for echo quorum...");
        _echoLatch.await(10, TimeUnit.SECONDS);

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
        }

        System.out.println("Waiting for ready quorum...");
        _readyLatch.await(10, TimeUnit.SECONDS);

        EchoMessage readyMessage = compareMessages(_readys);

        if (readyMessage == null) {
            System.out.println("No ready quorum.");
            throw new RemoteException("No ready quorum.");
        }

        System.out.println("Ready quorum. Delivering message.");
        _echos.clear();
        _echoLatch = new CountDownLatch(3);
        _readys.clear();
        _readyLatch = new CountDownLatch(3);
        return readyMessage;
    }

    @Override
    public void echo(EchoMessage message) {

        if (!message.getOp().equals("register")) {
            Account senderAccount = _accounts.get(message.getPubKey());
            senderAccount.echo(message, loadPublicKey(message.getServerId()));
            return;
        }

        if (message.verify(loadPublicKey(message.getServerId()), message.serialize())) {
            System.out.println("(echo) Verified");
            Account.addEcho(message, _echos, _echoLatch);
        } else {
            System.out.println("(echo) Not verified");
        }
    }

    @Override
    public void ready(EchoMessage message) {

        if (!message.getOp().equals("register")) {
            Account senderAccount = _accounts.get(message.getPubKey());
            senderAccount.ready(message, loadPublicKey(message.getServerId()));
            return;
        }

        if (message.verify(loadPublicKey(message.getServerId()), message.serialize())) {
            System.out.println("(ready) Verified");
            Account.addReady(message, _readys, _readyLatch);
        } else {
            System.out.println("(ready) Not verified");
        }
    }
}
