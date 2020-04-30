package secforum;

import java.rmi.Remote;
import java.security.PublicKey;
import java.util.List;

public class EchoMessageRegister extends EchoMessage {

    public EchoMessageRegister(PublicKey pubKey) {
        super(pubKey);
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

    @Override
    public byte[] getSignature() {
        return new byte[0];
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

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
