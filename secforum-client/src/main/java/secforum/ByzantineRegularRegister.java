package secforum;

import secforum.response.Response;

import java.util.ArrayList;

public class ByzantineRegularRegister {
    private ArrayList<Integer> _acklist;
    private int _rid;
    private ArrayList<Response> _readlist;

    public ByzantineRegularRegister() {
        _acklist = new ArrayList<>();
        _rid = 0;
        _readlist = new ArrayList<>();
    }

    public ArrayList<Integer> getAcklist() {
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

    public ArrayList<Response> getReadlist() {
        return _readlist;
    }

    public synchronized void setReadlist(Response response) {
        _readlist.add(response);
    }

    public synchronized void clearReadlist() {
        _readlist.clear();
    }
}
