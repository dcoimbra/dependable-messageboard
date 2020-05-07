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
    private final byte[] _requestSignature;

    public EchoMessageRead(int serverId, PublicKey pubKey, PublicKey targetKey, int number, int rid, Remote clientStub,
                           byte[] requestSignature, PrivateKey privKey, int nonce) {
        super(serverId,"read", pubKey, nonce);
        _targetKey = targetKey;
        _number = number;
        _rid = rid;
        _clientStub = clientStub;
        _requestSignature = requestSignature;
        sign(privKey);
    }

    public EchoMessageRead(EchoMessageRead message, int id, PrivateKey privKey, int nonce) {
        super(message, id, nonce);
        _targetKey = message.getTargetKey();
        _number = message.getNumber();
        _rid = message.getRid();
        _clientStub = message.getClientStub();
        _requestSignature = message.getRequestSignature();
        sign(privKey);
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
        return Utils.serializeMessage(getOp(), getPubKey(), _targetKey, _number, _rid, _clientStub, getNonce());
    }

    public PublicKey getTargetKey() {
        return _targetKey;
    }

    public int getRid() {
        return _rid;
    }

    public int getNumber() {
        return _number;
    }

    public Remote getClientStub() {
        return _clientStub;
    }

    public byte[] getRequestSignature() {
        return _requestSignature;
    }
}
