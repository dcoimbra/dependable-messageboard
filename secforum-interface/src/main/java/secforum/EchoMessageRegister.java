package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class EchoMessageRegister extends EchoMessage {
    public EchoMessageRegister(PublicKey pubKey, PrivateKey _privKey) {
        super("register", pubKey);
        sign(_privKey);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey());
    }
}
