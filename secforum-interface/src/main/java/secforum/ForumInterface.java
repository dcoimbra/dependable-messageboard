package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    public void register(String username) throws RemoteException;

    public void post(String username, String message, List<Announcement> a) throws RemoteException;

    public void postGeneral(String username, String message, List<Announcement> a) throws RemoteException;

    public List<Announcement> read(String username, int number) throws RemoteException;

    public List<Announcement> readGeneral(int number) throws RemoteException;
}
