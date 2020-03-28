package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    Response register(PublicKey pubKey) throws RemoteException;

    Response post(PublicKey pubKey, String message, List<String> ids, LocalDateTime timestamp, byte[] signature) throws RemoteException;

    Response postGeneral(PublicKey pubKey, String message, List<String> ids, LocalDateTime timestamp, byte[] signature) throws RemoteException;

    Response read(PublicKey senderPubKey, PublicKey pubKey, int number, byte[] signature) throws RemoteException;

    Response readGeneral(PublicKey senderPubKey, int number, byte[] signature) throws RemoteException;
}
