package secforum;

import java.rmi.RemoteException;
import java.security.PublicKey;

public class RegisterRequest  implements Runnable {
    private PublicKey _publicKey;
    private ForumInterface _forum;
    private PublicKey _serverKey;

    public RegisterRequest(ForumInterface forum, PublicKey publicKey, PublicKey serverKey) {
        _forum = forum;
        _publicKey = publicKey;
        _serverKey = serverKey;
    }

    @Override
    public void run() {

        try {
            Response res = _forum.register(_publicKey);
            res.verify(_serverKey, 0, 0);
        } catch (RemoteException e) {
            System.out.println(e.detail.toString());
        }
    }
}
