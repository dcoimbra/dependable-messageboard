package secforum;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.List;

public class Forum extends UnicastRemoteObject implements ForumInterface {

    private List<Account> _accounts;
    private Board _generalBoard;

    public Forum() throws RemoteException {
        _accounts = new ArrayList<>();
        _generalBoard = new Board();
    }

    public void register(String username) throws RemoteException {
        if (findAccountByUsername(username) == null) {
            throw new RemoteException(username + " already registered.");
        }

        _accounts.add(new Account(username));
    }

    public void post(String name, String message, Announcement[] a) throws RemoteException {

    }

    public void postGeneral(String name, String message, Announcement[] a) throws RemoteException {

    }

    public List<Announcement> read(String name, int number) throws RemoteException {
        return null;
    }

    public List<Announcement> readGeneral(int number) throws RemoteException {
        return null;
    }

    private Account findAccountByUsername(String username) {
        for (Account account : _accounts) {
            if (account.getUsername().equals(username)) {
                return account;
            }
        }
        return null;
    }
}
