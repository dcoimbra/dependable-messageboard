package secforum;

import java.rmi.RemoteException;
import java.security.PublicKey;

public class EchoRequest implements Runnable {

    private EchoMessage _message;
    private ForumReliableBroadcastInterface _server;

    public EchoRequest(EchoMessage message, ForumReliableBroadcastInterface server) {
        _message = message;
        _server = server;
    }

    @Override
    public void run() {
        try {
            _server.echo(_message);
        } catch (RemoteException e) {
            System.out.println("Echo error.");
        }
    }
}
