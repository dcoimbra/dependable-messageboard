package secforum;

import java.rmi.Remote;
import java.security.PublicKey;
import java.util.List;

public class EchoMessageRead extends EchoMessage {
     private PublicKey _targetPubKey;
     private int _number;
     private int _rid;
     private Remote _clientStub;
     private byte[] _signature;

    public EchoMessageRead(PublicKey pubKey, PublicKey targetPubKey, int number, int rid, Remote clientStub, byte[] signature) {
        super(pubKey);
        _targetPubKey = targetPubKey;
        _number = number;
        _rid = rid;
        _clientStub = clientStub;
        _signature = signature;
    }

    public PublicKey getTargetPubKey() {
    return _targetPubKey;
}

    public int getNumber() {
        return _number;
    }

    public int getRid() {
        return _rid;
    }

    public Remote getClientStub() {
        return _clientStub;
    }

    @Override
    public String getMessage() {
        return null;
    }

    @Override
    public List<String> getQuotedAnnouncements() {
        return null;
    }

    @Override
    public int getWts() {
        return 0;
    }

    public byte[] getSignature() {
        return _signature;
    }
}
