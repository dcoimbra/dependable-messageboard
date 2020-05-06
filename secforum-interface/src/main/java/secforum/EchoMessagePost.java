package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class EchoMessagePost extends EchoMessage {

    private final String _message;
    private final List<String> _quotedAnnouncements;
    private final int _wts;

    public EchoMessagePost(PublicKey pubKey, String message, List<String> quotedAnnouncements, int wts,
                           PrivateKey _privKey) {
        super("post", pubKey);
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _wts = wts;
        sign(_privKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessagePost that = (EchoMessagePost) o;
        return _wts == that._wts &&
                _message.equals(that._message) &&
                _quotedAnnouncements.equals(that._quotedAnnouncements);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey(), _message, _quotedAnnouncements, _wts);
    }
}
