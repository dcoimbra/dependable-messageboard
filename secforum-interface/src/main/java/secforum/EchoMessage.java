package secforum;

import security.SigningSHA256_RSA;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class EchoMessage implements Serializable {
    private int _serverId;
    private final PublicKey _pubKey;
    private final String _op;
    private byte[] _signature;
    private int _nonce;


    public EchoMessage(int serverId, String op, PublicKey pubKey, int nonce) {
        _serverId = serverId;
        _op = op;
        _pubKey = pubKey;
        _nonce = nonce;
    }

    public EchoMessage(EchoMessage message, int id, int nonce) {
        _serverId = id;
        _op = message._op;
        _pubKey = message.getPubKey();
        _nonce = nonce;
    }


    public PublicKey getPubKey() {
        return _pubKey;
    }
    public String getOp() { return _op; }
    public int getServerId() { return _serverId; }
    public void setServerId(int id) { _serverId = id; }
    public int getNonce() { return _nonce; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EchoMessage that = (EchoMessage) o;
        return _pubKey.equals(that._pubKey) &&
                _op.equals(that._op);
    }

    public void sign(PrivateKey privKey) {
        byte[] messageBytes = serialize();
        setSignature(SigningSHA256_RSA.sign(messageBytes, privKey));
    }

    public boolean verify(PublicKey serverKey, byte[] serializedMessage) {
        return SigningSHA256_RSA.verify(serializedMessage, getSignature(), serverKey);
    }

    protected void setSignature(byte[] signature) {
        _signature = signature;
    }

    protected byte[] getSignature() {
        return _signature;
    }

    public abstract byte[] serialize();

    public void setNonce(int nonce) {
        _nonce = nonce;
    }
}

