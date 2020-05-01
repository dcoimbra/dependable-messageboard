package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ExceptionResponse extends Response {
    private RemoteException _exception;

    private static final String SECURITY_ERROR = "\nSecurity error! Response was altered!";

    public ExceptionResponse(RemoteException exception, PrivateKey privKey, Integer nonce) {
        super(nonce, privKey, exception);
        _exception = exception;
    }

    @Override
    public RemoteException getException() {
        return _exception;
    }

    @Override
    public int getId() { throw new IllegalArgumentException(); }

    @Override
    public boolean verify(PublicKey serverKey, Integer nonce, int requestID) {
        byte[] messageBytes = Utils.serializeMessage(_exception, nonce);

        if(SigningSHA256_RSA.verify(messageBytes, _signature, serverKey)) {
            System.out.println(_exception.getMessage());
            return false;
        }

        throw new IllegalArgumentException(SECURITY_ERROR);
    }

    @Override
    public Integer verifyNonce(PublicKey serverKey) throws IllegalArgumentException {
        byte[] messageBytes = Utils.serializeMessage(_exception, -1);

        if(SigningSHA256_RSA.verify(messageBytes, _signature, serverKey)) {
            throw new IllegalArgumentException(_exception.getMessage());
        }

        throw new IllegalArgumentException(SECURITY_ERROR);
    }
}
