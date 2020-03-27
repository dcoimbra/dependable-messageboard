package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    public boolean register(PublicKey pubKey) throws RemoteException;

    public boolean verifyRegistered(PublicKey pubKey) throws RemoteException;

    public void post(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp, String signature) throws RemoteException;

    public void postGeneral(PublicKey pubKey, String message, List<Announcement> a, LocalDateTime timestamp, String signature) throws RemoteException;

    public List<Announcement> read(PublicKey senderPubKey, PublicKey pubKey, int number, String signature) throws RemoteException;

    public List<Announcement> readGeneral(PublicKey senderPubKey, int number, String signature) throws RemoteException;

    public String hello(String message) throws RemoteException;
}
