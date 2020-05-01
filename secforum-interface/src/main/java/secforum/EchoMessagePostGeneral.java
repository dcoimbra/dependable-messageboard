package secforum;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

public class EchoMessagePostGeneral extends EchoMessage {

    private String _message;
    private List<String> _quotedAnnouncements;
    private int _nonce;
    private int _rid;
    private int _wts;
    private int _rank;

    public EchoMessagePostGeneral(PublicKey pubKey, String message, List<String> quotedAnnouncements, int rid, int wts, int rank) {
        super("postGeneral", pubKey);
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _rid = rid;
        _wts = wts;
        _rank = rank;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessagePostGeneral that = (EchoMessagePostGeneral) o;
        return _nonce == that._nonce &&
                _rid == that._rid &&
                _wts == that._wts &&
                _rank == that._rank &&
                _message.equals(that._message) &&
                _quotedAnnouncements.equals(that._quotedAnnouncements);
    }
}
