package secforum;

import secforum.response.Response;
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
    private int _rank;
    private int _rid;
    private final ByzantineRegularRegister _regularRegisterGeneral;

    public PostGeneralRequest(ForumInterface forum, PrivateKey privateKey, PublicKey publicKey, PublicKey serverKey,
                              String message, List<String> quotedAnnouncements, int wts, int rank, int rid,
                              ByzantineRegularRegister regularRegisterGeneral) {
        _forum = forum;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _serverKey = serverKey;
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _wts = wts;
        _rank = rank;
        _rid = rid;
        _regularRegisterGeneral = regularRegisterGeneral;
    }

    @Override
    public void run() {
        try {

            Response res = _forum.getNonce(_publicKey);
            Integer nonce = res.verifyNonce(_serverKey);

            byte[] announcementBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, nonce, _wts, _rank);
            byte[] announcementSignature = SigningSHA256_RSA.sign(announcementBytes, _privateKey);

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, nonce, _rid, _wts, _rank);
            byte[] signature = SigningSHA256_RSA.sign(messageBytes, _privateKey);

            res = _forum.postGeneral(_publicKey, _message, _quotedAnnouncements, _rid, _wts, _rank, signature, announcementSignature);

            try {
                if(res.verify(_serverKey, nonce + 1, _rid)) {
                    _regularRegisterGeneral.setAcklistValue();
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
