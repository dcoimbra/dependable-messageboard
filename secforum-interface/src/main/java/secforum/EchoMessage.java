package secforum;

import java.io.Serializable;
import java.rmi.Remote;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public abstract class EchoMessage implements Serializable {
    private PublicKey _pubKey;
    private String _op;

    public EchoMessage(String op, PublicKey pubKey) {
        _op = op;
        _pubKey = pubKey;
    }

    public PublicKey getPubKey() {
        return _pubKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EchoMessage that = (EchoMessage) o;
        return _pubKey.equals(that._pubKey) &&
                _op.equals(that._op);
    }
}

