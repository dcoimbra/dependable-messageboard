package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class WriteResponse extends Response {
    private String _response;
    private int _ts;

    public WriteResponse(String response, PrivateKey privKey, Integer nonce, int ts) {
        super(nonce, privKey, response, ts);
        _response = response;
        _ts = ts;
    }

    @Override
    public String getResponse() {
        return _response;
    }

    @Override
    public boolean verify(PublicKey pubKey, Integer nonce, int ts) {
        byte[] messageBytes = Utils.serializeMessage(_response, nonce, ts);

        if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
            System.out.println(_response);
            return true;
        } else {
            throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
        }
    }

    @Override
    public boolean verify(PublicKey pubKey, Integer nonce) { throw new IllegalArgumentException(); }

    @Override
    public boolean verify(PublicKey serverKey, PublicKey publicKey, Integer nonce, int rid) throws IllegalArgumentException {
        throw new IllegalArgumentException();
    }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException { throw new IllegalArgumentException(); }

    @Override
    public int getId() {
        return _ts;
    }
}
