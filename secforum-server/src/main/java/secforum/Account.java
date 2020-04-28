package secforum;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Account implements Serializable {

    private PublicKey _pubKey;
    private Board _announcementsBoard;
    private int _counter;
    private Integer _nonce;
    private int _ts;
    private Map<ClientCallbackInterface, Integer> _listeners;

    public Account(PublicKey pubKey) {
        _pubKey = pubKey;
        _announcementsBoard = new Board();
        _counter = 0;
        _nonce = 0;
        _ts = 0;
        _listeners = new HashMap<>();
    }

    protected Map<ClientCallbackInterface, Integer> getListeners() {
        return _listeners;
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

    public synchronized Announcement post(String message, List<Announcement> a, byte[] signature, int wts) throws RemoteException {
        if (wts > _ts) {
            setTs(wts);
            Announcement announcement = _announcementsBoard.post(_pubKey, message, a, _nonce, signature, _counter, wts);
            _counter++;
            return announcement;
        } else {
            throw new RemoteException("Error. This request was already processed.");
        }
    }

    public List<Announcement> read(int number, ClientCallbackInterface listener) throws RemoteException {
        _listeners.put(listener, number);
        return _announcementsBoard.read(number);
    }

    protected List<Announcement> read(int number) throws RemoteException {
        return _announcementsBoard.read(number);
    }
}
