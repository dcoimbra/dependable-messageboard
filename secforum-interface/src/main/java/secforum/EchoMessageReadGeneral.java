package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class EchoMessageReadGeneral extends EchoMessage {
    private final int _number;
    private final int _rid;

    public EchoMessageReadGeneral(PublicKey pubKey, int number, int rid, PrivateKey _privKey) {
        super("readGeneral", pubKey);
        _number = number;
        _rid = rid;
        sign(_privKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessageReadGeneral that = (EchoMessageReadGeneral) o;
        return _number == that._number &&
                _rid == that._rid;
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey(), _number, _rid);
    }
}
