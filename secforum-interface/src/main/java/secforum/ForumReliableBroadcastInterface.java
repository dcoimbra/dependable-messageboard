package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.List;

public interface ForumReliableBroadcastInterface extends Remote {
     void echo(EchoMessage message) throws RemoteException;
     void ready(EchoMessage message) throws RemoteException;
}
