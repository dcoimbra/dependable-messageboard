package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ForumReliableBroadcastInterface extends Remote {
     void echo(EchoMessage message) throws RemoteException;
     void ready(EchoMessage message) throws RemoteException;
}
