package secforum;

import java.rmi.RemoteException;

public class EchoRequest implements Runnable {

    private final EchoMessage _message;
    private final ForumReliableBroadcastInterface _server;

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
