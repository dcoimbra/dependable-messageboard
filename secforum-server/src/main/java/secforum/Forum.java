/*
  @author GROUP 25
 * Main class that represents a forum
 */

package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
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
    }

    /**
     *
     * @param username of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @throws RemoteException
     */
    public void post(String username, String message, List<Announcement> a) throws RemoteException {
        if (!_accounts.containsKey(username)) {
            throw new RemoteException(username + " does not exist");
        }

        Account account = _accounts.get(username);
        account.post(message, a);
    }

    /**
     *
     * @param username of the user who is posting
     * @param message to be posted
     * @param a quoted announcements
     * @throws RemoteException
     */
    public void postGeneral(String username, String message, List<Announcement> a) throws RemoteException {
        if (!_accounts.containsKey(username)) {
            throw new RemoteException(username + " does not exist");
        }

        _generalBoard.post(username, message, a);
    }

    /**
     *
     * @param username of the user to read from
     * @param number of posts to read
     * @return read posts
     * @throws RemoteException
     */
    public List<Announcement> read(String username, int number) throws RemoteException {
        Account account = _accounts.get(username);

        if (account == null) {
            throw new RemoteException(username + " does not exist");
        }

        return account.read(number);
    }

    /**
     *
     * @param number of posts to read
     * @return read posts
     * @throws RemoteException
     */
    public List<Announcement> readGeneral(int number) throws RemoteException {
        return _generalBoard.read(number);
    }
}
