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
    private final int _rank;
    private final ByzantineAtomicRegister _atomicRegister;
    private final boolean _firstTime;

    public PostRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey serverKey,
                       String message, List<String> quotedAnnouncements, int rank,
                       ByzantineAtomicRegister atomicRegister, boolean firstTime) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _serverKey = serverKey;
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _rank = rank;
        _atomicRegister = atomicRegister;
        _firstTime = firstTime;
    }

    @Override
    public void run() {
        try {
            int wts;

            if (_firstTime) {
                Response res = _forum.getTs(_publicKey);
                wts = res.verifyNonce(_serverKey);
                wts++;
                _atomicRegister.setWts(wts);
            }

            else {
                wts = _atomicRegister.getWts();
            }

            Response res = _forum.getNonce(_publicKey);
            Integer nonce = res.verifyNonce(_serverKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, nonce, wts, _rank);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            res = _forum.post(_publicKey, _message, _quotedAnnouncements, wts, _rank, signature);

            try {
                if (res.verify(_serverKey, nonce + 1, wts)) {
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
