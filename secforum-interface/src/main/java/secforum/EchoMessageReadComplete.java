package secforum;

import security.Utils;

import java.rmi.Remote;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EchoMessageReadComplete extends EchoMessage {
    Remote _clientStub;
    int _rid;
    byte[] _requestSignature;

    public EchoMessageReadComplete(int serverId, PublicKey publicKey, Remote clientStub, int rid, byte[] requestSignature,
                                   PrivateKey privKey, int nonce) {
        super(serverId, "readComplete", publicKey, nonce);
        _clientStub = clientStub;
        _rid = rid;
        _requestSignature = requestSignature;
        sign(privKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessageReadComplete that = (EchoMessageReadComplete) o;
        return _rid == that._rid &&
                _clientStub.equals(that._clientStub);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey(), _clientStub, _rid, getNonce());
    }

    public Remote getClientStub() {
        return _clientStub;
    }

    public int getRid() {
        return _rid;
    }

    public byte[] getRequestSignature() {
        return _requestSignature;
    }
}
