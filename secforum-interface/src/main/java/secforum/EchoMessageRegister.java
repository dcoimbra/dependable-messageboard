package secforum;

import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class EchoMessageRegister extends EchoMessage {
    public EchoMessageRegister(int serverId, PublicKey pubKey, PrivateKey _privKey) {
        super(serverId,"register", pubKey, 0);
        sign(_privKey);
    }

    @Override
    public byte[] serialize() {
        return Utils.serializeMessage(getOp(), getPubKey(), getNonce());
    }
}
