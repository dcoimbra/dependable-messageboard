package secforum;

import secforum.response.Response;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ClientCallbackInterface extends Remote {
    void writeBack(Response res) throws RemoteException;
}
