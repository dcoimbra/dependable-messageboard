package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    public void register(String name) throws RemoteException;

    public void post(String name, String message, Announcement[] a) throws RemoteException;

    public void postGeneral(String name, String message, Announcement[] a) throws RemoteException;

    public Announcement[] read(String name, int number) throws RemoteException;

    public Announcement[] readGeneral(int number) throws RemoteException;
}
