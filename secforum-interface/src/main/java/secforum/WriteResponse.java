package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class WriteResponse extends Response {
    private String _response;

    public WriteResponse(String response, PrivateKey privKey, Integer nonce) {
        super(nonce, privKey, response);
        _response = response;
    }

    @Override
    public String getResponse() {
        return _response;
    }

    @Override
    public void verify(PublicKey pubKey, Integer nonce) {

        try {
            byte[] messageBytes = Utils.serializeMessage(_response, nonce);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
                System.out.println(_response);
            } else {
                throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned");
        }
    }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException { throw new IllegalArgumentException(); }
}
