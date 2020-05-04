package secforum;

import security.SigningSHA256_RSA;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class EchoMessage implements Serializable {
    private final PublicKey _pubKey;
    private final String _op;
    private byte[] _signature;


    public EchoMessage(String op, PublicKey pubKey) {
        _op = op;
        _pubKey = pubKey;
    }


    public PublicKey getPubKey() {
        return _pubKey;
    }
    public String getOp() { return _op; }

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
}

