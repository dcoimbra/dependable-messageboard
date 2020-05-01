package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ReadGeneralRequest implements Runnable {

    private PublicKey _serverKey;
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private ForumInterface _forum;
    private int _nAnnouncement;
    private Integer _rid;
    private final ByzantineRegularRegister _regularRegisterGeneral;

    public ReadGeneralRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey serverKey,
                       int nAnnouncement, int rid, ByzantineRegularRegister regularRegisterGeneral) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _serverKey = serverKey;
        _nAnnouncement = nAnnouncement;
        _rid = rid;
        _regularRegisterGeneral = regularRegisterGeneral;
    }

    @Override
    public void run() {
        try {
            Response res = _forum.getNonce(_publicKey);
            Integer nonce = res.verifyNonce(_serverKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _nAnnouncement, nonce, _rid);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            res = _forum.readGeneral(_publicKey, _nAnnouncement, _rid, signature);

            try {
                if(res.verify(_serverKey, nonce + 1, _rid)) {
                    synchronized (_regularRegisterGeneral) {
                        _regularRegisterGeneral.setReadlist(res);
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
