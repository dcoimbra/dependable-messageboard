package secforum;

import java.security.PublicKey;

public class EchoMessageRegister extends EchoMessage {
    public EchoMessageRegister(PublicKey pubKey) {
        super("register", pubKey);
    }
}
