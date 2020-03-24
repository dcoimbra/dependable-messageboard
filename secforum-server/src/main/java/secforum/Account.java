package secforum;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.List;

public class Account implements Serializable {

    private PublicKey _pubKey;
    private Board _announcementsBoard;

    public Account(PublicKey pubKey) {
        _pubKey = pubKey;
        _announcementsBoard = new Board();
    }

    public PublicKey getPubKey() {
        return _pubKey;
    }

    public void post(String message,  List<Announcement> a) throws IllegalArgumentException {
        _announcementsBoard.post(_pubKey, message, a);
    }

    public List<Announcement> read(int number) throws IllegalArgumentException {
        return _announcementsBoard.read(number);
    }
}
