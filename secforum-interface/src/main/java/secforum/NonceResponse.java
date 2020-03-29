package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.io.Serializable;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public class NonceResponse implements Serializable {

    Integer _nonce;
    private byte[] _signature;

    public NonceResponse(Integer nonce, PrivateKey privKey) {
        _nonce = nonce;
        List<Object> toSerialize = new ArrayList<>();
        byte[] messageBytes;
        toSerialize.add(nonce);

        try {
            messageBytes = Utils.serializeMessage(toSerialize);
            _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Integer getNonce() {
        return _nonce;
    }

    public byte[] getSignature() {
        return _signature;
    }
}
