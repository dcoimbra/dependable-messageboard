package secforum;

import security.Signing_RSA;
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
            throw new RemoteException(pubKey.toString() + " already registered.");
        }

        String text;
        PrivateKey privKey = loadPrivateKey();

        if(privKey == null) throw new RemoteException("Internal server error");

        try {
            synchronized (this) {
                ForumServer.writeForum(this);
            }
            text = "Registered successfully";
        } catch (IOException e) {
            e.printStackTrace();
            text = "Failed to register";
        }

        return new Response(null, text, privKey);
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
    public synchronized Response post(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        if (!verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey.toString() + " does not exist");
        }

        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(pubKey);
        toSerialize.add(message);
        toSerialize.add(a);
        toSerialize.add(timestamp);

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!Signing_RSA.verify(messageBytes, signature, pubKey)) {
                throw new RemoteException("post: Security error.");
            }
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        Account account = _accounts.get(pubKey);

        try {
            synchronized (this) {
                account.post(message, a, timestamp, signature);
                ForumServer.writeForum(this);
            }
        } catch (IllegalArgumentException | IOException e) {
            throw new RemoteException(e.getMessage());
        }

        System.out.println(pubKey.toString() + " just posted in their board");

        PrivateKey privKey = loadPrivateKey();
        if(privKey == null) throw new RemoteException("Internal server error");

        return new Response(null, "Successfully uploaded the post", privKey);
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @param signature
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized Response postGeneral(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp, byte[] signature) throws RemoteException {
        if (!verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey.toString() + " does not exist");
        }

        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(pubKey);
        toSerialize.add(message);
        toSerialize.add(a);
        toSerialize.add(timestamp);

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!Signing_RSA.verify(messageBytes, signature, pubKey)) {
                throw new RemoteException("post: Security error.");
            }
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        try {
            synchronized (this) {
                _generalBoard.post(pubKey, message, a, timestamp, signature);
                ForumServer.writeForum(this);
            }
        } catch (IllegalArgumentException | IOException e) {
            throw new RemoteException(e.getMessage());
        }

        System.out.println(pubKey.toString() + " just posted in the general board");

        PrivateKey privKey = loadPrivateKey();
        if(privKey == null) throw new RemoteException("Internal server error");

        return new Response(null, "Successfully uploaded the post", privKey);
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
            throw new RemoteException(pubKey.toString() + " does not exist");
        }

        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(senderPubKey);
        toSerialize.add(pubKey);
        toSerialize.add(number);

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!Signing_RSA.verify(messageBytes, signature, senderPubKey)) {
                throw new RemoteException("post: Security error.");
            }
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        try {
            PrivateKey privKey = loadPrivateKey();
            if(privKey == null) throw new RemoteException("Internal server error");

            List<Announcement> list = account.read(number);
            System.out.println("Reading " + list.size() + " posts from " + pubKey.toString() + "'s board");

            return new Response(list, null, privKey);
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

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            if (!Signing_RSA.verify(messageBytes, signature, senderPubKey)) {
                throw new RemoteException("post: Security error.");
            }
        } catch (IOException e) {
            throw new RemoteException("Internal server error");
        }

        try {
            PrivateKey privKey = loadPrivateKey();
            if(privKey == null) throw new RemoteException("Internal server error");

            List<Announcement> list = _generalBoard.read(number);
            System.out.println("Reading " + list.size() + " posts from the general board");

            return new Response(list, null, privKey);
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
}
