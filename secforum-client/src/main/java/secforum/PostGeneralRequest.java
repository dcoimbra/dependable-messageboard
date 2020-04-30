package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class PostGeneralRequest implements Runnable {

    private PublicKey _serverKey;
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private ForumInterface _forum;
    private String _message;
    private List<String> _quotedAnnouncements;
    private Integer _wts;
    private final ByzantineRegularRegister _regularRegisterGeneral;

    public PostGeneralRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey serverKey,
                              String message, List<String> quotedAnnouncements, int wts,
                              ByzantineRegularRegister regularRegisterGeneral) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _serverKey = serverKey;
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _wts = wts;
        _regularRegisterGeneral = regularRegisterGeneral;
    }

    @Override
    public void run() {
        try {
            Response res = _forum.getNonce(_publicKey);
            Integer nonce = res.verifyNonce(_serverKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, nonce, _wts);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            res = _forum.postGeneral(_publicKey, _message, _quotedAnnouncements, _wts, signature);

            try {
                if (res.verify(_serverKey, nonce + 1, _wts)) {
                    synchronized (_regularRegisterGeneral) {
                        _regularRegisterGeneral.setAcklistValue();
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
