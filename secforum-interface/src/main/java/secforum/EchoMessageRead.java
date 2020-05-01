package secforum;

import java.rmi.Remote;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

public class EchoMessageRead extends EchoMessage {

    private PublicKey _targetKey;
    private int _rid;
    private int _number;
    private Remote _clientStub;
    private byte[] _signature;

    public EchoMessageRead(PublicKey pubKey, PublicKey targetKey, int number, int rid, Remote clientStub, byte[] signature) {
        super("read", pubKey);
        _targetKey = targetKey;
        _number = number;
        _rid = rid;
        _clientStub = clientStub;
        _signature = signature;
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
                _clientStub.equals(that._clientStub) &&
                Arrays.equals(_signature, that._signature);
    }
}
