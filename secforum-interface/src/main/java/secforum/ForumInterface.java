package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    public void register(String username) throws RemoteException;

    public boolean verifyRegistered(String username) throws RemoteException;

    public void post(String username, String message, List<Announcement> a, LocalDateTime timestamp) throws RemoteException;

    public void postGeneral(String username, String message, List<Announcement> a, LocalDateTime timestamp) throws RemoteException;

    public List<Announcement> read(String username, int number) throws RemoteException;

    public List<Announcement> readGeneral(int number) throws RemoteException;

    public String hello(String message) throws RemoteException;
}
