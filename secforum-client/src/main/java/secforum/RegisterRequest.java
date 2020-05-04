package secforum;

import secforum.response.Response;

import java.rmi.RemoteException;
import java.security.PublicKey;

public class RegisterRequest  implements Runnable {
    private final PublicKey _publicKey;
    private final ForumInterface _forum;
    private final PublicKey _serverKey;

    public RegisterRequest(ForumInterface forum, PublicKey publicKey, PublicKey serverKey) {
        _forum = forum;
        _publicKey = publicKey;
        _serverKey = serverKey;
    }

    @Override
    public void run() {

        try {
            Response res = _forum.register(_publicKey);
            res.verify(_serverKey, 0, -1);
        } catch (RemoteException e) {
            System.out.println(e.detail.toString());
        }
    }
}
