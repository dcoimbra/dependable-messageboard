package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class ExceptionResponse extends Response {
    private RemoteException _exception;

    public ExceptionResponse(RemoteException exception, PrivateKey privKey, Integer nonce) {
        super(nonce, privKey, exception);
        _exception = exception;
    }

    @Override
    public RemoteException getException() {
        return _exception;
    }

    @Override
    public void verify(PublicKey pubKey, Integer nonce) {
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(_exception);
        toSerialize.add(nonce);

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
                System.out.println(_exception.getCause());
            } else {
                throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned");
        }
    }
}
