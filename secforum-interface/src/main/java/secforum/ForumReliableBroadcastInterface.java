package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.List;

public interface ForumReliableBroadcastInterface extends Remote {
     void echoRegister(EchoMessageRegister message) throws RemoteException;

     void echoPost(EchoMessagePost message) throws RemoteException;

     void echoPostGeneral(EchoMessagePost message) throws RemoteException;

     void echoRead(EchoMessageRead message) throws RemoteException;

     void echoReadGeneral(EchoMessageRead message) throws RemoteException;

     void readyRegister(EchoMessageRegister message) throws RemoteException;

     void readyPost(EchoMessagePost message) throws RemoteException;

     void readyPostGeneral(EchoMessagePost message) throws RemoteException;

     void readyRead(EchoMessageRead message) throws RemoteException;

     void readyReadGeneral(EchoMessageRead message) throws RemoteException;
}
