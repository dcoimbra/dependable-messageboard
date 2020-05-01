package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public abstract class Response implements Serializable {
    protected byte[] _signature;

    public Response(Integer nonce, PrivateKey privKey, Object response) {
        byte[] messageBytes;

        if(response == null) {
            messageBytes = Utils.serializeMessage(nonce);
        } else {
            messageBytes = Utils.serializeMessage(response, nonce);
        }

        _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
    }

    public Response(Integer nonce, PrivateKey privKey, Object response, int ts) {
        byte[] messageBytes = Utils.serializeMessage(response, nonce, ts);
        _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
    }

    public String getResponse() { return null; }

    public List<Announcement> getAnnouncements() {
        return null;
    }

    public RemoteException getException() {
        return null;
    }

    public abstract int getId() throws IllegalArgumentException;

    public abstract boolean verify(PublicKey publicKey, Integer nonce, int requestID) throws IllegalArgumentException;

    public abstract Integer verifyNonce(PublicKey serverKey) throws IllegalArgumentException;
}
