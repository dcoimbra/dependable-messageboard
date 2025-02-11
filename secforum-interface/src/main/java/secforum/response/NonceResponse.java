package secforum.response;

import security.SigningSHA256_RSA;
import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class NonceResponse extends Response {
    private final Integer _nonce;

    public NonceResponse(PrivateKey privKey, Integer nonce) {
        super(nonce, privKey);
        _nonce = nonce;
    }

    @Override
    public boolean verify(PublicKey serverKey, Integer nonce, int requestID) { throw new IllegalArgumentException(); }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException {
        byte[] messageBytes = Utils.serializeMessage(_nonce);

        if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
            return _nonce;
        }
        throw new IllegalArgumentException("\nSecurity error! Response was altered!");
    }
}
