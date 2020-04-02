package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class Response implements Serializable {
    protected Integer _nonce;
    protected byte[] _signature;

    public Response(Integer nonce, PrivateKey privKey, Object object) {
        _nonce = nonce;

        sign(object, privKey);
    }

    public Response(Integer nonce, PrivateKey privKey) {
        _nonce = nonce;

        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(_nonce);

        try {
            byte[] messageBytes = serialize(toSerialize);
            _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

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

    protected void sign(Object object, PrivateKey privKey) {
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(object);
        toSerialize.add(_nonce);

        try {
            byte[] messageBytes = serialize(toSerialize);
            _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Integer verifyNonce(PublicKey pubKey) throws IllegalArgumentException {
        List<Object> toSerialize = new ArrayList<>();
        toSerialize.add(_nonce);

        try {
            byte[] messageBytes = Utils.serializeMessage(toSerialize);

            if(SigningSHA256_RSA.verify(messageBytes, _signature, pubKey)) { return _nonce; }

        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Nonce was not returned");
        }
        throw new IllegalArgumentException("ERROR. SECURITY VIOLATION WAS DETECTED!!");
    }

    public abstract void verify(PublicKey pubKey, Integer nonce) throws IllegalArgumentException;

    private byte[] serialize(Object object) throws IOException {
        List<Object> toSerialize = Arrays.asList(object, _nonce);

        return Utils.serializeMessage(toSerialize);

    }
}
