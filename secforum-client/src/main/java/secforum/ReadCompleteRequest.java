package secforum;

import secforum.response.Response;
import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ReadCompleteRequest implements Runnable {

    private final PublicKey _serverKey;
    private final PublicKey _publicKey;
    private final PrivateKey _privateKey;
    private final ForumInterface _forum;
    private final Remote _clientStub;
    private final int _rid;

    public ReadCompleteRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey serverKey,
                               Remote clientStub, int rid) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _serverKey = serverKey;
        _clientStub = clientStub;
        _rid = rid;
    }

    @Override
    public void run() {
        try {
            Response res = _forum.getNonce(_publicKey);
            int nonce = res.verifyNonce(_serverKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _clientStub, nonce, _rid);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            _forum.readComplete(_publicKey, _clientStub, _rid, signature);
        } catch (RemoteException e) {
            System.out.println(e.detail.toString());
        }
    }
}
