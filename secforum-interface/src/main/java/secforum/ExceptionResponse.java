package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
        try {
            byte[] messageBytes = Utils.serializeMessage(_exception, nonce);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) {
                System.out.println(_exception.getMessage());
            } else {
                throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned:");
        }
    }

    @Override
    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException { throw new IllegalArgumentException(); }
}
