package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    Response getNonce(PublicKey pubKey) throws RemoteException;

    Response register(PublicKey pubKey) throws RemoteException;

    Response post(PublicKey pubKey, String message, List<String> ids, int wts, byte[] signature) throws RemoteException;

    Response postGeneral(PublicKey pubKey, String message, List<String> ids, byte[] signature) throws RemoteException;

    Response read(PublicKey senderPubKey, PublicKey pubKey, int number, int rid, byte[] signature) throws RemoteException;

    Response readGeneral(PublicKey senderPubKey, int number, byte[] signature) throws RemoteException;
}
