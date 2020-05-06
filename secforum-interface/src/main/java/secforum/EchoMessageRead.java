package secforum;

import security.Utils;

import java.rmi.Remote;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EchoMessageRead extends EchoMessage {

    private final PublicKey _targetKey;
    private final int _rid;
    private final int _number;
    private final Remote _clientStub;

    public EchoMessageRead(PublicKey pubKey, PublicKey targetKey, int number, int rid, Remote clientStub,
                           PrivateKey _privKey) {
        super("read", pubKey);
        _targetKey = targetKey;
        _number = number;
        _rid = rid;
        _clientStub = clientStub;
        sign(_privKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessageRead that = (EchoMessageRead) o;
        return _rid == that._rid &&
                _number == that._number &&
                _targetKey.equals(that._targetKey) &&
                _clientStub.equals(that._clientStub);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey(), _targetKey, _number, _rid, _clientStub);
    }
}
