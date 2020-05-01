package secforum;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

public class EchoMessageReadGeneral extends EchoMessage {
    private int _number;
    private int _rid;

    public EchoMessageReadGeneral(PublicKey pubKey, int number, int rid) {
        super("readGeneral", pubKey);
        _number = number;
        _rid = rid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EchoMessageReadGeneral that = (EchoMessageReadGeneral) o;
        return _number == that._number &&
                _rid == that._rid;
    }
}
