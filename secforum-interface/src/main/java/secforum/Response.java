package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public abstract class Response implements Serializable {
    protected Integer _nonce;
    protected byte[] _signature;

    public Integer getNonce() { return _nonce; }

    public byte[] getSignature() {
        return _signature;
    }

    public String getResponse() { return null; }

    public List<Announcement> getAnnouncements() {
        return null;
    }

    public RemoteException getException() {
        return null;
    }

    public Response(Integer nonce, PrivateKey privKey, Object object) {
        _nonce = nonce;

        sign(object, privKey);
    }

    public Response(Integer nonce, PrivateKey privKey) {
        _nonce = nonce;

        byte[] messageBytes = Utils.serializeMessage(_nonce);
        _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
    }

    protected void sign(Object object, PrivateKey privKey) {
        byte[] messageBytes = Utils.serializeMessage(object, _nonce);
        _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
    }

    public abstract void verify(PublicKey pubKey, Integer nonce) throws IllegalArgumentException;

    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException {
        try {
            byte[] messageBytes = Utils.serializeMessage(_nonce);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) { return _nonce; }

        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned");
        }
        throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
    }
}
