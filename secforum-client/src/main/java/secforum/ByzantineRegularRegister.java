package secforum;

import secforum.response.Response;

import java.util.List;
import java.util.Vector;

public class ByzantineRegularRegister {
    private final List<Integer> _acklist;
    private int _rid;
    private final List<Response> _readlist;

    public ByzantineRegularRegister() {
        _acklist = new Vector<>();
        _rid = 0;
        _readlist = new Vector<>();
    }

    public List<Integer> getAcklist() {
        return _acklist;
    }

    public void setAcklistValue() {
        _acklist.add(1);
    }

    public synchronized void clearAcklist() {
        _acklist.clear();
    }

    public int getRid() {
        return _rid;
    }

    public synchronized void setRid() {
        _rid++;
    }

    public List<Response> getReadlist() {
        return _readlist;
    }

    public synchronized void setReadlist(Response response) {
        _readlist.add(response);
    }

    public synchronized void clearReadlist() {
        _readlist.clear();
    }
}
