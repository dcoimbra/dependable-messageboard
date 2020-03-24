package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    public void register(PublicKey pubKey) throws RemoteException;

    public boolean verifyRegistered(PublicKey pubKey) throws RemoteException;

    public void post(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp) throws RemoteException;

    public void postGeneral(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp) throws RemoteException;

    public List<Announcement> read(PublicKey pubKey, int number) throws RemoteException;

    public List<Announcement> readGeneral(int number) throws RemoteException;

    public String hello(String message) throws RemoteException;
}
