package secforum;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class Account implements Serializable {

    private PublicKey _pubKey;
    private Board _announcementsBoard;
    private int _counter;
    private Integer _nonce;
    private int _ts;
    private List<ClientCallbackInterface> _listeners;

    public Account(PublicKey pubKey) {
        _pubKey = pubKey;
        _announcementsBoard = new Board();
        _counter = 0;
        _nonce = 0;
        _ts = 0;
        _listeners = new ArrayList<>();
    }

    public void setTs(int wts) { _ts = wts; }

    public int getTs() { return _ts; }

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

    public synchronized List<ClientCallbackInterface> post(String message, List<Announcement> a, byte[] signature, int wts) throws RemoteException {
        if (wts > _ts) {
            setTs(wts);
            _announcementsBoard.post(_pubKey, message, a, _nonce, signature, _counter, wts);
            _counter++;

           return _listeners;

        } else {
            throw new RemoteException("Error. This request was already processed.");
        }
    }

    public List<Announcement> read(int number, ClientCallbackInterface listener) throws RemoteException {
        _listeners.add(listener);
        return _announcementsBoard.read(number);
    }
}
