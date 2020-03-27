/**
 * @author GROUP 25
 * Main class that represents a forum
 */

package secforum;

import security.Signing_RSA;

import java.io.IOException;
import java.io.Serializable;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.PublicKey;
import java.time.LocalDateTime;
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
     */
    public synchronized boolean register(PublicKey pubKey) throws RemoteException {
        if (_accounts.putIfAbsent(pubKey, new Account(pubKey)) != null) {
            throw new RemoteException(pubKey.toString() + " already registered.");
        }

        try {
            synchronized (this) {
                ForumServer.writeForum(this);
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean verifyRegistered(PublicKey pubKey) throws RemoteException {
         return _accounts.containsKey(pubKey);
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized void post(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp, String signature) throws RemoteException {
        if (!verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey.toString() + " does not exist");
        }

        String original = pubKey.toString() + message + a.toString() + timestamp.toString();
        if (!Signing_RSA.verify(original, signature, pubKey)) {
            throw new RemoteException("post: Security error.");
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
    }

    /**
     *
     * @param pubKey of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @throws RemoteException if no account with this pubKey
     */
    public synchronized void postGeneral(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp, String signature) throws RemoteException {
        if (!verifyRegistered(pubKey)) {
            throw new RemoteException(pubKey.toString() + " does not exist");
        }

        String original = pubKey.toString() + message + a.toString() + timestamp.toString();
        if (!Signing_RSA.verify(original, signature, pubKey)) {
            throw new RemoteException("postGeneral: Security error.");
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
    }

    /**
     *
     * @param pubKey of the user to read from
     * @param number of posts to read
     * @return read posts
     * @throws RemoteException if no account with this pubKey
     */
    public List<Announcement> read(PublicKey senderPubKey, PublicKey pubKey, int number, String signature) throws RemoteException {
        Account account = _accounts.get(pubKey);

        if (account == null) {
            throw new RemoteException(pubKey.toString() + " does not exist");
        }

        String original = senderPubKey.toString() + pubKey.toString() + Integer.toString(number);
        if (!Signing_RSA.verify(original, signature, senderPubKey)) {
            throw new RemoteException("read: security error.");
        }

        try {
            List<Announcement> list = account.read(number);
            System.out.println("Reading " + list.size() + " posts from " + pubKey.toString() + "'s board");
            return list;
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }
    }

    /**
     *
     * @param number of posts to read
     * @return read posts
     * @throws RemoteException if trying to read more than total number of announcements
     */
    public List<Announcement> readGeneral(PublicKey senderPubKey, int number, String signature) throws RemoteException {

        String original = senderPubKey.toString() + Integer.toString(number);
        if (!Signing_RSA.verify(original, signature, senderPubKey)) {
            throw new RemoteException("read: security error.");
        }

        try {
            List<Announcement> list = _generalBoard.read(number);
            System.out.println("Reading " + list.size() + " posts from the general board");
            return list;
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }
    }

    public String hello(String message) throws RemoteException {
        return "hello " + message;
    }
}
