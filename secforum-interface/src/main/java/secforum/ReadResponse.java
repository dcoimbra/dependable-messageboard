package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class ReadResponse extends Response {
    private List<Announcement> _announcements;

    public ReadResponse(List<Announcement> announcements, PrivateKey privKey, Integer nonce) {
        super(nonce, privKey, announcements);
        _announcements = announcements;
    }

    @Override
    public List<Announcement> getAnnouncements() {
        return _announcements;
    }

    @Override
    public boolean verify(PublicKey pubKey, Integer nonce) {
        try {
            byte[] messageBytes = Utils.serializeMessage(_announcements, nonce);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
                return true;
            } else {
                throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned");
        }
    }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException { throw new IllegalArgumentException(); }
}
