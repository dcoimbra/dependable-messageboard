package secforum;

import java.security.PrivateKey;
import java.security.PublicKey;

public class NonceResponse extends Response {

    public NonceResponse(PrivateKey privKey, Integer nonce) {
        super(nonce, privKey);
    }

    @Override
    public void verify(PublicKey pubKey, Integer nonce) { return; }
}
