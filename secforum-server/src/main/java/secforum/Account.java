package secforum;

import java.io.Serializable;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

public class Account implements Serializable {

    private PublicKey _pubKey;
    private Board _announcementsBoard;
    private int _counter;
    private Integer _nonce;

    public Account(PublicKey pubKey) {
        _pubKey = pubKey;
        _announcementsBoard = new Board();
        _counter = 0;
        _nonce = 0;
    }

    public PublicKey getPubKey() {
        return _pubKey;
    }

    public int getCounter() {
        return _counter++;
    }

    public Integer getNonce() {
        return _nonce;
    }

    public void setNonce() {
        _nonce = _nonce + 1;
    }

    public List<Announcement> getBoardAnnouncements() {
        return _announcementsBoard.getAnnouncements();
    }

    public void post(String message, List<Announcement> a, LocalDateTime timestamp, byte[] signature) throws IllegalArgumentException {
        _announcementsBoard.post(_pubKey, message, a, timestamp, signature, _counter);
        _counter++;
    }

    public List<Announcement> read(int number) throws IllegalArgumentException {
        return _announcementsBoard.read(number);
    }
}
