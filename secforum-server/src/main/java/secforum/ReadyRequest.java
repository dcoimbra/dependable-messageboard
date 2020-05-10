package secforum;

import java.rmi.RemoteException;

public class ReadyRequest implements Runnable {

    private final EchoMessage _message;
    private final ForumReliableBroadcastInterface _server;

    public ReadyRequest(EchoMessage message, ForumReliableBroadcastInterface server) {
        _message = message;
        _server = server;
    }

    @Override
    public void run() {
        try {
            _server.ready(_message);
        } catch (RemoteException | InterruptedException e) {
            System.out.println("Ready error.");
        }
    }
}
