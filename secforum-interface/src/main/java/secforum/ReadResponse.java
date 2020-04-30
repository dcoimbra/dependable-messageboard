package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class ReadResponse extends Response {
    private List<Announcement> _announcements;
    private int _rid;

    public ReadResponse(List<Announcement> announcements, PrivateKey privKey, Integer nonce, int rid) {
        super(nonce, privKey, announcements, rid);
        _announcements = announcements;
        _rid = rid;
    }

    @Override
    public List<Announcement> getAnnouncements() {
        return _announcements;
    }

    @Override
    public int getId() { return _rid; }

    @Override
    public boolean verify(PublicKey pubKey, Integer nonce) { throw new IllegalArgumentException(); }

    @Override
    public boolean verify(PublicKey serverKey, Integer nonce, int requestID) {
        byte[] messageBytes = Utils.serializeMessage(_announcements, nonce, requestID);

        if (SigningSHA256_RSA.verify(messageBytes, _signature, serverKey)) {
            for (Announcement announcement : _announcements) {
                if (!announcement.verify(announcement.getPubKey())) {
                    throw new IllegalArgumentException("ERROR. Signature mismatch: server is byzantine.");
                }
            }

            return true;
        } else {
            throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
        }
    }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException { throw new IllegalArgumentException(); }
}
