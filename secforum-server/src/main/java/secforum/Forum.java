/**
 * @author GROUP 25
 * Main class that represents a forum
 */

package secforum;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Forum extends UnicastRemoteObject implements ForumInterface {

    private Map<String, Account> _accounts;
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
     * @param username of the user who is registered
     * @throws RemoteException if the user is already registered
     */
    public void register(String username) throws RemoteException {
        if (_accounts.putIfAbsent(username, new Account(username)) != null) {
            throw new RemoteException(username + " already registered.");
        }

        System.out.println("Registered " + username);
    }

    public boolean verifyRegistered(String username) throws RemoteException {
         return _accounts.containsKey(username);
    }

    /**
     *
     * @param username of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @throws RemoteException if no account with this username
     */
    public void post(String username, String message, List<Announcement> a, LocalDateTime timestamp) throws RemoteException {
        if (!_accounts.containsKey(username)) {
            throw new RemoteException(username + " does not exist");
        }

        Account account = _accounts.get(username);

        try {
            account.post(message, a);
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }

        System.out.println(username + " just posted in their board");
    }

    /**
     *
     * @param username of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @throws RemoteException if no account with this username
     */
    public void postGeneral(String username, String message, List<Announcement> a, LocalDateTime timestamp) throws RemoteException {
        if (!_accounts.containsKey(username)) {
            throw new RemoteException(username + " does not exist");
        }

        try {
            _generalBoard.post(username, message, a);
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }

        System.out.println(username + " just posted in the general board");
    }

    /**
     *
     * @param username of the user to read from
     * @param number of posts to read
     * @return read posts
     * @throws RemoteException if no account with this username
     */
    public List<Announcement> read(String username, int number) throws RemoteException {
        Account account = _accounts.get(username);

        if (account == null) {
            throw new RemoteException(username + " does not exist");
        }

        try {
            List<Announcement> list = account.read(number);
            System.out.println("Reading " + number + " posts from " + username + "'s board");
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
    public List<Announcement> readGeneral(int number) throws RemoteException {
        try {
            List<Announcement> list = _generalBoard.read(number);
            System.out.println("Reading " + number + " posts from the general board");
            return list;
        } catch (IllegalArgumentException iae) {
            throw new RemoteException(iae.getMessage());
        }
    }

    public String hello(String message) throws RemoteException {
        return "hello " + message;
    }
}
