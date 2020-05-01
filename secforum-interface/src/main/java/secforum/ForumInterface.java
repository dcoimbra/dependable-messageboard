package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.List;

/** Forum remote interface. */
public interface ForumInterface extends Remote {
    Response getNonce(PublicKey pubKey) throws RemoteException;

    Response register(PublicKey pubKey) throws RemoteException;

    Response post(PublicKey pubKey, String message, List<String> ids, int wts, int rank, byte[] signature) throws RemoteException;

    Response read(PublicKey senderPubKey, PublicKey pubKey, int number, int rid, Remote clientStub, byte[] signature) throws RemoteException;

    Response postGeneral(PublicKey pubKey, String message, List<String> ids, int rid, int ts, int rank, byte[] requestSignature, byte[] announcementSignature) throws RemoteException;

    Response readGeneral(PublicKey senderPubKey, int number, int rid, byte[] signature) throws RemoteException;

    Response readComplete(PublicKey pubkey, Remote clientStub, int rid, byte[] signature) throws RemoteException;
}
