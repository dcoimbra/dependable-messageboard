package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

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
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(_response);
        toSerialize.add(nonce);

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
                System.out.println(_response);
            } else {
                throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned");
        }
    }
}
