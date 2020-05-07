package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class EchoMessagePostGeneral extends EchoMessage {

    private final String _message;
    private final List<String> _quotedAnnouncements;
    private final int _rid;
    private final int _wts;
    private final int _rank;
    private final byte[] _requestSignature;
    private final byte[] _announcementSignature;

    public EchoMessagePostGeneral(int serverId, PublicKey pubKey, String message, List<String> quotedAnnouncements,
                                  int rid, int wts, int rank, byte[] requestSignature, byte[] announcementSignature,
                                  PrivateKey privKey, int nonce) {
        super(serverId,"postGeneral", pubKey, nonce);
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _rid = rid;
        _wts = wts;
        _rank = rank;
        _requestSignature = requestSignature;
        _announcementSignature = announcementSignature;
        sign(privKey);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessagePostGeneral that = (EchoMessagePostGeneral) o;
        return _rid == that._rid &&
                _wts == that._wts &&
                _rank == that._rank &&
                _message.equals(that._message) &&
                _quotedAnnouncements.equals(that._quotedAnnouncements);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey(), _message, _quotedAnnouncements, _rid, _wts, _rank,
                getNonce());
    }

    public String getMessage() {
        return _message;
    }

    public List<String> getQuotedAnnouncements() {
        return _quotedAnnouncements;
    }

    public int getRid() {
        return _rid;
    }

    public int getWts() {
        return _wts;
    }

    public int getRank() {
        return _rank;
    }

    public byte[] getRequestSignature() {
        return _requestSignature;
    }

    public byte[] getAnnouncementSignature() {
        return _announcementSignature;
    }
}
