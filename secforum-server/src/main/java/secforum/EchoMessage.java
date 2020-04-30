package secforum;

import java.rmi.Remote;
import java.security.PublicKey;
import java.util.List;

public abstract class EchoMessage {
    private PublicKey _pubKey;

    public EchoMessage(PublicKey pubKey) {
        _pubKey = pubKey;
    }

    public PublicKey getPubKey() {
        return _pubKey;
    }

    public abstract String getMessage();

    public abstract List<String> getQuotedAnnouncements();

    public abstract int getWts();

    public abstract byte[] getSignature();

    public abstract int getNumber();

    public abstract int getRid();

    public abstract Remote getClientStub();
}

