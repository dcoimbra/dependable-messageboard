package secforum;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class Forum extends UnicastRemoteObject implements ForumInterface {

    public Forum() throws RemoteException {}

    public void register(String name) throws RemoteException {

    }

    public void post(String name, String message, Announcement[] a) throws RemoteException {

    }

    public void postGeneral(String name, String message, Announcement[] a) throws RemoteException {

    }

    public Announcement[] read(String name, int number) throws RemoteException {
        return null;
    }

    public Announcement[] readGeneral(int number) throws RemoteException {
        return null;
    }
}
