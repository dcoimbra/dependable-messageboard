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
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Forum extends UnicastRemoteObject implements ForumInterface, Serializable {

    private Map<PublicKey, Account> _accounts;
    private Board _generalBoard;

    /**
     *
     * @throws RemoteException
     */
    public Forum() throws RemoteException {
        _accounts = new HashMap<>();
        _generalBoard = new Board();
    }

    /**
     *
     * @param pubKey of the user who is registered
     * @throws RemoteException if the user is already registered
     * @return
     */
    public synchronized Response register(PublicKey pubKey) throws RemoteException {
        if (_accounts.putIfAbsent(pubKey, new Account(pubKey)) != null) {
            throw new RemoteException(pubKey + " already registered.");
        }

        String text;
        PrivateKey privKey = loadPrivateKey();

        if (privKey == null) throw new RemoteException("Internal server error");

        try {
            synchronized (this) {
                ForumServer.writeForum(this);
            }
            text = "Registered successfully";
        } catch (IOException e) {
            e.printStackTrace();
            text = "Failed to register";
        }

        Response res = new Response(null, text, privKey, _accounts.get(pubKey).getNonce());
        _accounts.get(pubKey).setNonce();
        return res;
    }

    public boolean verifyRegistered(PublicKey pubKey) throws RemoteException {
         return _accounts.containsKey(pubKey);
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param signature
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized Response post(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        if(!verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey + " does not exist");
        }

        List<Announcement> announcements;
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(pubKey);
        toSerialize.add(message);
        toSerialize.add(a);
        toSerialize.add(timestamp);
        toSerialize.add(_accounts.get(pubKey).getNonce());

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!SigningSHA256_RSA.verify(messageBytes, signature, pubKey)) {
                throw new RemoteException("post: Security error.");
            }

            announcements = verifyAnnouncements(a);
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        } catch (IllegalArgumentException e) {
            _accounts.get(pubKey).setNonce();
            throw new RemoteException("Quoted announcement does not exist");
        }

        Account account = _accounts.get(pubKey);
        account.setNonce();

        try {
            synchronized (this) {
                account.post(message, announcements, timestamp, signature);
                ForumServer.writeForum(this);
            }
        } catch (IllegalArgumentException | IOException e) {
            throw new RemoteException(e.getMessage());
        }

        System.out.println(pubKey + " just posted in their board");

        PrivateKey privKey = loadPrivateKey();
        if(privKey == null) throw new RemoteException("Internal server error");

        Response res = new Response(null, "Successfully uploaded the post", privKey, account.getNonce());
        account.setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param signature
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized Response postGeneral(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        if (!verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey + " does not exist");
        }

        List<Announcement> announcements;
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(pubKey);
        toSerialize.add(message);
        toSerialize.add(a);
        toSerialize.add(timestamp);
        toSerialize.add(_accounts.get(pubKey).getNonce());

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!SigningSHA256_RSA.verify(messageBytes, signature, pubKey)) {
                throw new RemoteException("post: Security error.");
            }

            announcements = verifyAnnouncements(a);
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        } catch (IllegalArgumentException e) {
            _accounts.get(pubKey).setNonce();
            throw new RemoteException("Quoted announcement does not exist");
        }

        _accounts.get(pubKey).setNonce();

        try {
            synchronized (this) {
                _generalBoard.post(pubKey, message, announcements, timestamp, signature, _accounts.get(pubKey).getCounter());
                ForumServer.writeForum(this);
            }
        } catch (IllegalArgumentException | IOException e) {
            throw new RemoteException(e.getMessage());
        }

        System.out.println(pubKey + " just posted in the general board");

        PrivateKey privKey = loadPrivateKey();
        if(privKey == null) throw new RemoteException("Internal server error");

        Response res = new Response(null, "Successfully uploaded the post", privKey, _accounts.get(pubKey).getNonce());
        _accounts.get(pubKey).setNonce();
        return res;
    }

    /**
     *
     * @param pubKey of the user to read from
     * @param number of posts to read
     * @param signature
     * @return read posts
     * @throws RemoteException if no account with this pubKey
     */
    public Response read(PublicKey senderPubKey, PublicKey pubKey, int number, byte[] signature) throws RemoteException {
        Account account = _accounts.get(pubKey);

        if (account == null) {
            throw new RemoteException(pubKey + " does not exist");
        }

        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(senderPubKey);
        toSerialize.add(pubKey);
        toSerialize.add(number);
        toSerialize.add(_accounts.get(senderPubKey).getNonce());

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!SigningSHA256_RSA.verify(messageBytes, signature, senderPubKey)) {
                throw new RemoteException("post: Security error.");
            }
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        _accounts.get(senderPubKey).setNonce();

        try {
            PrivateKey privKey = loadPrivateKey();
            if(privKey == null) throw new RemoteException("Internal server error");

            List<Announcement> list = account.read(number);
            System.out.println("Reading " + list.size() + " posts from " + pubKey + "'s board");

            Response res = new Response(list, null, privKey, _accounts.get(senderPubKey).getNonce());
            _accounts.get(senderPubKey).setNonce();
            return res;
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }
    }

    /**
     *
     * @param number of posts to read
     * @param signature
     * @return read posts
     * @throws RemoteException if trying to read more than total number of announcements
     */
    public Response readGeneral(PublicKey senderPubKey, int number, byte[] signature) throws RemoteException {

        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(senderPubKey);
        toSerialize.add(number);
        toSerialize.add(_accounts.get(senderPubKey).getNonce());

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!SigningSHA256_RSA.verify(messageBytes, signature, senderPubKey)) {
                throw new RemoteException("readGeneral: Security error.");
            }
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        _accounts.get(senderPubKey).setNonce();

        try {
            PrivateKey privKey = loadPrivateKey();
            if(privKey == null) throw new RemoteException("Internal server error");

            List<Announcement> list = _generalBoard.read(number);
            System.out.println("Reading " + list.size() + " posts from the general board");

            Response res = new Response(list, null, privKey, _accounts.get(senderPubKey).getNonce());
            _accounts.get(senderPubKey).setNonce();
            return res;
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }
    }

    private static PrivateKey loadPrivateKey() {
        FileInputStream fis;
        try {
            fis = new FileInputStream("src/main/resources/keystoreserver.jks");
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(fis, ("server").toCharArray());
            return (PrivateKey) keystore.getKey("server", ("server").toCharArray());
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private List<Announcement> verifyAnnouncements(List<String> announcementIDs) throws IllegalArgumentException {
        List<Announcement> announcements = new ArrayList<>();

        for(String id : announcementIDs) {
            Announcement announcement = announcementExists(id);

            if(announcement == null) {
                throw new IllegalArgumentException("Announcement " + id + " does not exist");
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
