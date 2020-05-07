package secforum;

import secforum.response.Response;
import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class PostRequest implements Runnable {

    private final PublicKey _serverKey;
    private final PublicKey _publicKey;
    private final PrivateKey _privateKey;
    private final ForumInterface _forum;
    private final String _message;
    private final List<String> _quotedAnnouncements;
    private final Integer _wts;
    private final int _rank;
    private final ByzantineAtomicRegister _atomicRegister;

    public PostRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey serverKey,
                       String message, List<String> quotedAnnouncements, int wts, int rank,
                       ByzantineAtomicRegister atomicRegister) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _serverKey = serverKey;
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _wts = wts;
        _rank = rank;
        _atomicRegister = atomicRegister;
    }

    @Override
    public void run() {
        try {
            Response res = _forum.getNonce(_publicKey);
            Integer nonce = res.verifyNonce(_serverKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, nonce, _wts, _rank);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            res = _forum.post(_publicKey, _message, _quotedAnnouncements, _wts, _rank, signature);

            try {
                if (res.verify(_serverKey, nonce + 1, _wts)) {
                    synchronized (_atomicRegister) {
                        _atomicRegister.setAcklistValue();
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
