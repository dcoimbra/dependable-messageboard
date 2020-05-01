package secforum.response;

import secforum.Announcement;
import security.SigningSHA256_RSA;
import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class ReadResponse extends Response {
    private List<Announcement> _announcements;

    private static final String SECURITY_ERROR = "\nSecurity error! Response was altered!";

    public ReadResponse(List<Announcement> announcements, PrivateKey privKey, Integer nonce, int rid) {
        super(nonce, privKey, announcements, rid);
        _announcements = announcements;
    }

    @Override
    public List<Announcement> getAnnouncements() {
        return _announcements;
    }

    @Override
    public boolean verify(PublicKey serverKey, Integer nonce, int requestID) {
        byte[] messageBytes = Utils.serializeMessage(_announcements, nonce, requestID);

        if (SigningSHA256_RSA.verify(messageBytes, _signature, serverKey)) {
            for (Announcement announcement : _announcements) {
                if (!announcement.verify()) {
                    throw new IllegalArgumentException(SECURITY_ERROR);
                }
            }
            return true;
        }

        throw new IllegalArgumentException(SECURITY_ERROR);
    }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException { throw new IllegalArgumentException(); }
}
