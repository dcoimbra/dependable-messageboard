package secforum;

import java.rmi.RemoteException;
import java.security.PublicKey;

public class ReadyRequest implements Runnable {

    private EchoMessage _message;
    private ForumReliableBroadcastInterface _server;

    public ReadyRequest(EchoMessage message, ForumReliableBroadcastInterface server) {
        _message = message;
        _server = server;
    }

    @Override
    public void run() {
        try {
            _server.ready(_message);
        } catch (RemoteException e) {
            System.out.println("Ready error.");
        }
    }
}
