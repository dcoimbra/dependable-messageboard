package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class ReadRequest implements Runnable {

    private PublicKey _serverKey;
    private PublicKey _publicKey;
    private PublicKey _targetKey;
    private PrivateKey _privateKey;
    private ForumInterface _forum;
    private int _nAnnouncement;
    private Integer _rid;
    private Remote _clientStub;
    private final ByzantineAtomicRegister _atomicRegister;

    public ReadRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey targetKey,
                       PublicKey serverKey, int nAnnouncement, int rid, Remote clientStub,
                       ByzantineAtomicRegister atomicRegister) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _targetKey = targetKey;
        _serverKey = serverKey;
        _nAnnouncement = nAnnouncement;
        _rid = rid;
        _clientStub = clientStub;
        _atomicRegister = atomicRegister;
    }

    @Override
    public void run() {
        try {
            Response res = _forum.getNonce(_publicKey);
            Integer nonce = res.verifyNonce(_serverKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _targetKey, _nAnnouncement, nonce, _rid, _clientStub);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            res = _forum.read(_publicKey, _targetKey, _nAnnouncement, _rid, _clientStub, signature);

            try {
                if(res.verify(_serverKey, _targetKey, nonce + 1, _rid)) {
                    synchronized (_atomicRegister) {
                        _atomicRegister.setAnswers(res);
                    }
                }
            } catch (IllegalArgumentException e) {
                System.out.println(e.getMessage());
                System.out.println("Not acknowledged. Carrying on...");
            }
        } catch (RemoteException e) {
            System.out.println(e.detail.toString());
        }
    }
}
