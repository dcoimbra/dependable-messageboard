package secforum;

import security.HashingMD5;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Forum extends UnicastRemoteObject implements ForumInterface, Serializable {

    private Map<PublicKey, Account> _accounts;
    private Board _generalBoard;
    private PrivateKey _privKey;
    private final ExceptionResponse _notClient;

    /**
     *
     * @throws RemoteException if there is a remote error
     */
    public Forum(String password) throws RemoteException {
        _accounts = new HashMap<>();
        _generalBoard = new Board();

        FileInputStream fis;
        try {
            fis = new FileInputStream("src/main/resources/keystoreserver.jks");
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(fis, (password).toCharArray());
            _privKey = (PrivateKey) keystore.getKey("server", (password).toCharArray());
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | IOException e) {
            System.out.println("Server could not load private key. SHUTTING DOWN!!!");
            System.exit(0);
        }

        _notClient = new ExceptionResponse(new RemoteException("This public key is not registered."), _privKey, 0);
    }


    public Response getNonce(PublicKey pubKey) {
        if(!verifyRegistered(pubKey)){
            System.out.println("Client got nonce = " + _accounts.get(pubKey).getNonce());
            return new NonceResponse(_privKey, _accounts.get(pubKey).getNonce());
        }

        return _notClient;
    }


    /**
     *
     * @param pubKey of the user who is registered
     * @throws RemoteException if the user is already registered
     * @return Response positive if successfully registered
     */
    public synchronized Response register(PublicKey pubKey) {
        Response res;

        if(_accounts.putIfAbsent(pubKey, new Account(pubKey)) != null) {
            res = new ExceptionResponse(new RemoteException("This public key is already registered."), _privKey, 0);
        } else {
            String text = "Registered successfully.";
            System.out.println("Someone was registered successfully.");

            res = new WriteResponse(text, _privKey, _accounts.get(pubKey).getNonce());
        }

        try {
            ForumServer.writeForum(this);
        } catch (IOException e) {
            res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, _accounts.get(pubKey).getNonce());
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
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized Response post(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) {
        Account account = _accounts.get(pubKey);
        if(account == null) {
            return _notClient;
        }

        Response res;

        try {
            List<Announcement> announcements = getQuotedAnnouncements(pubKey, message, a, timestamp, signature);

            account.post(message, announcements, timestamp, signature);
            System.out.println("Someone just posted in their board.");

            account.setNonce();
            res = new WriteResponse("Successfully uploaded the post.", _privKey, account.getNonce());
            ForumServer.writeForum(this);
        } catch (RemoteException re) {
            account.setNonce();
            res = new ExceptionResponse(re, _privKey, account.getNonce());
        } catch (IOException e) {
            res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, account.getNonce());
        }

        account.setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param signature of the sender
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized Response postGeneral(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) {
        Account account = _accounts.get(pubKey);
        if(account == null) {
            return _notClient;
        }

        Response res;
        try {
            List<Announcement> announcements = getQuotedAnnouncements(pubKey, message, a, timestamp, signature);

            _generalBoard.post(pubKey, message, announcements, timestamp, account.getNonce(), signature, account.getCounter());
            System.out.println("Someone just posted in the general board.");

            account.setNonce();
            res = new WriteResponse("Successfully uploaded the post.", _privKey, account.getNonce());
            ForumServer.writeForum(this);
        } catch (RemoteException re) {
            account.setNonce();
            res = new ExceptionResponse(re, _privKey, account.getNonce());
        } catch (IOException ioe) {
            res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, account.getNonce());
        }

        account.setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user to read from
     * @param number of posts to read
     * @param signature of the sender
     * @return Response read posts
     * @throws RemoteException if no account with this pubKey
     */
    public Response read(PublicKey senderPubKey, PublicKey pubKey, int number, byte[] signature) {
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        Response res;

        Account targetAccount = _accounts.get(pubKey);
        if(targetAccount == null) {
            senderAccount.setNonce();
            res = new ExceptionResponse(new RemoteException("Target account does not exist."), _privKey, senderAccount.getNonce());
        } else if (number < 0) {
            senderAccount.setNonce();
            res = new ExceptionResponse(new RemoteException("The number of announcements to read must not be less than zero"), _privKey, senderAccount.getNonce());
        } else {
            List<Object> toSerialize = new ArrayList<>();
            toSerialize.add(senderPubKey);
            toSerialize.add(pubKey);
            toSerialize.add(number);
            toSerialize.add(senderAccount.getNonce());

            byte[] messageBytes = new byte[0];
            try {
                messageBytes = Utils.serializeMessage(toSerialize);
            } catch (IllegalArgumentException e) {
                senderAccount.setNonce();
                res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, senderAccount.getNonce());
            }

            try {
                if (!SigningSHA256_RSA.verify(messageBytes, signature, senderPubKey)) {
                    senderAccount.setNonce();
                    res = new ExceptionResponse(new RemoteException("Security error. Message was altered."), _privKey, senderAccount.getNonce());
                } else {
                    senderAccount.setNonce();
                    List<Announcement> list = targetAccount.read(number);
                    System.out.println("Reading " + list.size() + " posts from someone's board");

                    res = new ReadResponse(list, _privKey, senderAccount.getNonce());
                    ForumServer.writeForum(this);
                }
            } catch (RemoteException re) {
                res = new ExceptionResponse(re, _privKey, senderAccount.getNonce());
            } catch (IOException e) {
                res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, senderAccount.getNonce());
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
     * @throws RemoteException if trying to read more than total number of announcements
     */
    public Response readGeneral(PublicKey senderPubKey, int number, byte[] signature) {
        Account senderAccount = _accounts.get(senderPubKey);
        if(senderAccount == null) {
            return _notClient;
        }

        Response res;

        if(number < 0) {
            senderAccount.setNonce();
            res = new ExceptionResponse(new RemoteException("The number of announcements to read must not be less than zero"), _privKey, senderAccount.getNonce());
        } else {
            List<Object> toSerialize = new ArrayList<>();
            toSerialize.add(senderPubKey);
            toSerialize.add(number);
            toSerialize.add(_accounts.get(senderPubKey).getNonce());

            byte[] messageBytes = new byte[0];
            try {
                messageBytes = Utils.serializeMessage(toSerialize);
            } catch (IllegalArgumentException e) {
                senderAccount.setNonce();
                res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, senderAccount.getNonce());
            }

            try {
                if (!SigningSHA256_RSA.verify(messageBytes, signature, senderPubKey)) {
                    senderAccount.setNonce();
                    res = new ExceptionResponse(new RemoteException("Security error. Message was altered."), _privKey, senderAccount.getNonce());
                } else {
                    senderAccount.setNonce();
                    List<Announcement> list = _generalBoard.read(number);
                    System.out.println("Reading " + list.size() + " posts from the general board");

                    res = new ReadResponse(list, _privKey, senderAccount.getNonce());
                    ForumServer.writeForum(this);
                }
            } catch (RemoteException re) {
                res = new ExceptionResponse(re, _privKey, senderAccount.getNonce());
            } catch (IOException e) {
                res = new ExceptionResponse(new RemoteException("Internal server error."), _privKey, senderAccount.getNonce());
            }
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

    private List<Announcement> getQuotedAnnouncements(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(pubKey);
        toSerialize.add(message);
        toSerialize.add(a);
        toSerialize.add(timestamp);
        toSerialize.add(_accounts.get(pubKey).getNonce());

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!SigningSHA256_RSA.verify(messageBytes, signature, pubKey)) {
                throw new RemoteException("Security error. Message was altered.");
            }
            return verifyAnnouncements(a);
        } catch(IllegalArgumentException iae) {
            throw new RemoteException("Internal server error.");
        }
    }

    private List<Announcement> verifyAnnouncements(List<String> announcementIDs) throws RemoteException {
        List<Announcement> announcements = new ArrayList<>();

        for(String id : announcementIDs) {
            Announcement announcement = announcementExists(id);

            if(announcement == null) {
                throw new RemoteException("Announcement " + id + " does not exist");
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
                if(HashingMD5.equals(id, announcement.getId())) {
                    return announcement;
                }
            }
        }

        for(Announcement announcement : _generalBoard.getAnnouncements()) {
            if(HashingMD5.equals(id, announcement.getId())) {
                return announcement;
            }
        }

        return null;
    }

    protected Map<PublicKey, Account> getAccounts() {
        return _accounts;
    }
}
