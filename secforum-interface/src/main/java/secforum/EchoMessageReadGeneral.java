package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class EchoMessageReadGeneral extends EchoMessage {
    private final int _number;
    private final int _rid;
    private final byte[] _requestSignature;

    public EchoMessageReadGeneral(int serverId, PublicKey pubKey, int number, int rid, byte[] requestSignature,
                                  PrivateKey privKey, int nonce) {
        super(serverId, "readGeneral", pubKey, nonce);
        _number = number;
        _rid = rid;
        _requestSignature = requestSignature;
        sign(privKey);
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
        return Utils.serializeMessage(getOp(), getPubKey(), _number, _rid, getNonce());
    }

    public int getNumber() {
        return _number;
    }

    public int getRid() {
        return _rid;
    }

    public byte[] getRequestSignature() {
        return _requestSignature;
    }
}
