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
     * @throws RemoteException if there is a remote error
     */
    public Forum() throws RemoteException {
        _accounts = new HashMap<>();
        _generalBoard = new Board();
    }


    public NonceResponse getNonce(PublicKey pubKey) throws RemoteException {
        if (!verifyRegistered(pubKey)) {
            PrivateKey privKey = loadPrivateKey();
            if (privKey == null) throw new RemoteException("Internal server error");
            return new NonceResponse(_accounts.get(pubKey).getNonce(), privKey);
        }

        throw new RemoteException("You need to be registered.");
    }


    /**
     *
     * @param pubKey of the user who is registered
     * @throws RemoteException if the user is already registered
     * @return Response positive if successfully registered
     */
    public synchronized Response register(PublicKey pubKey) throws RemoteException {
        if (_accounts.putIfAbsent(pubKey, new Account(pubKey)) != null) {
            throw new RemoteException(pubKey + " already registered.");
        }

        String text;
        PrivateKey privKey = loadPrivateKey();

        if (privKey == null) throw new RemoteException("Internal server error");

        text = "Registered successfully";
        System.out.println("Someone was registered successfully");

        Response res = new Response(text, privKey, _accounts.get(pubKey).getNonce());
        _accounts.get(pubKey).setNonce();

        try {
            ForumServer.writeForum(this);
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        return res;
    }

    public boolean verifyRegistered(PublicKey pubKey) {
         return !_accounts.containsKey(pubKey);
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param signature signature of the sender
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized Response post(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        List<Announcement> announcements = verifyPost(pubKey, message, a, timestamp, signature);

        Account account = _accounts.get(pubKey);
        account.setNonce();

        account.post(message, announcements, timestamp, signature);

        System.out.println(pubKey + " just posted in their board");

        PrivateKey privKey = loadPrivateKey();
        if(privKey == null) throw new RemoteException("Internal server error");

        Response res = new Response("Successfully uploaded the post", privKey, account.getNonce());
        account.setNonce();

        try {
            ForumServer.writeForum(this);
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

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
    public synchronized Response postGeneral(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        List<Announcement> announcements = verifyPost(pubKey, message, a, timestamp, signature);

        _accounts.get(pubKey).setNonce();
        _generalBoard.post(pubKey, message, announcements, timestamp, signature, _accounts.get(pubKey).getCounter());

        System.out.println(pubKey + " just posted in the general board");

        PrivateKey privKey = loadPrivateKey();
        if(privKey == null) throw new RemoteException("Internal server error");

        Response res = new Response("Successfully uploaded the post", privKey, _accounts.get(pubKey).getNonce());
        _accounts.get(pubKey).setNonce();

        try {
            ForumServer.writeForum(this);
        } catch (IllegalArgumentException | IOException e) {
            throw new RemoteException(e.getMessage());
        }

        return res;
    }

    private List<Announcement> verifyPost(PublicKey pubKey, String message, List<String> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        if(verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey + " does not exist");
        }
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
            return verifyAnnouncements(a);
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        } catch (IllegalArgumentException e) {
            _accounts.get(pubKey).setNonce();
            throw new RemoteException("Quoted announcement does not exist");
        }
    }

    /**
     *
     * @param pubKey of the user to read from
     * @param number of posts to read
     * @param signature of the sender
     * @return Response read posts
     * @throws RemoteException if no account with this pubKey
     */
    public Response read(PublicKey senderPubKey, PublicKey pubKey, int number, byte[] signature) throws RemoteException {
        if (number < 0) {
            throw new RemoteException("read: number must not be less than zero");
        }

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

            Response res = new Response(list, privKey, _accounts.get(senderPubKey).getNonce());
            _accounts.get(senderPubKey).setNonce();
            return res;
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }
    }

    /**
     *
     * @param number of posts to read
     * @param signature of the sender
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

            Response res = new Response(list, privKey, _accounts.get(senderPubKey).getNonce());
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
