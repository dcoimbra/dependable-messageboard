package secforum;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface ClientCallbackInterface extends Remote {
    void writeBack(Response res) throws RemoteException;
}
