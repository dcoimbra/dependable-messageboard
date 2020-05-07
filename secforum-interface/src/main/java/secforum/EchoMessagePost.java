package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class EchoMessagePost extends EchoMessage {

    private final String _message;
    private final List<String> _quotedAnnouncements;
    private final int _wts;
    private final int _rank;
    private final byte[] _requestSignature;

    public EchoMessagePost(int serverId, PublicKey pubKey, String message, List<String> quotedAnnouncements, int wts, int rank,
                           byte[] requestSignature, PrivateKey privKey, int nonce) {
        super(serverId,"post", pubKey, nonce);
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _wts = wts;
        _rank = rank;
        _requestSignature = requestSignature;
        sign(privKey);
    }

    public EchoMessagePost(EchoMessagePost message, int id, PrivateKey privKey, int nonce) {
        super(message, id, nonce);
        _message = message.getMessage();
        _quotedAnnouncements = message.getQuotedAnnouncements();
        _wts = message.getWts();
        _rank = getRank();
        _requestSignature = message.getRequestSignature();
        sign(privKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessagePost that = (EchoMessagePost) o;
        return _wts == that._wts &&
                _rank == that._rank &&
                _message.equals(that._message) &&
                _quotedAnnouncements.equals(that._quotedAnnouncements);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getServerId(), getOp(), getPubKey(), _message, _quotedAnnouncements, _wts, _rank,
                getNonce());
    }

    public String getMessage() {
        return _message;
    }

    public List<String> getQuotedAnnouncements() {
        return _quotedAnnouncements;
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


}
