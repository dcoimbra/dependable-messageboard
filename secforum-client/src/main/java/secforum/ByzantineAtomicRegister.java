package secforum;

import secforum.response.Response;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ByzantineAtomicRegister {
    private int _wts;
    private final List<Integer> _acklist;
    private int _rid;
    private final List<Response> _answers;

    public ByzantineAtomicRegister() {
        _wts = 0;
        _acklist = new CopyOnWriteArrayList<>();
        _rid = 0;
        _answers = new CopyOnWriteArrayList<>();
    }

    public int getWts() {
        return _wts;
    }

    public synchronized void setWts() {
        _wts++;
    }

    public List<Integer> getAcklist() {
        return _acklist;
    }

    public synchronized void setAcklistValue() {
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

    public List<Response> getAnswers() {
        return _answers;
    }

    public synchronized void setAnswers(Response response) { _answers.add(response); }

    public synchronized void clearAnswers() {
        _answers.clear();
    }

}
