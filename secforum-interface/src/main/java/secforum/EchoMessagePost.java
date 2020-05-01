package secforum;

import java.rmi.Remote;
import java.security.PublicKey;
import java.util.List;

public class EchoMessagePost extends EchoMessage {
    private String _message;
    private List<String> _a;
    private int _wts;
    private byte[] _signature;

    public EchoMessagePost(PublicKey publicKey, String message, List<String> a, int wts, byte[] signature) {
        super(publicKey);
        _message = message;
        _a = a;
        _wts = wts;
        _signature = signature;
    }

    public String getMessage() {
        return _message;
    }

    public List<String> getQuotedAnnouncements() {
        return _a;
    }

    public int getWts() {
        return _wts;
    }

    public byte[] getSignature() {
        return _signature;
    }

    @Override
    public int getNumber() {
        return 0;
    }

    @Override
    public int getRid() {
        return 0;
    }

    @Override
    public Remote getClientStub() {
        return null;
    }
}
