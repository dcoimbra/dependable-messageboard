package secforum;

import java.util.ArrayList;
import java.util.List;

public class ByzantineAtomicRegister {
    private int _wts;
    private List<Integer> _acklist;
    private int _rid;
    private List<Response> _answers;

    public ByzantineAtomicRegister() {
        _wts = 0;
        _acklist = new ArrayList<>();
        _rid = 0;
        _answers = new ArrayList<>();
    }

    public int getWts() {
        return _wts;
    }

    public void setWts() {
        _wts++;
    }

    public List<Integer> getAcklist() {
        return _acklist;
    }

    public void setAcklistValue() {
        _acklist.add(1);
    }

    public void clearAcklist() {
        _acklist.clear();
    }

    public int getRid() {
        return _rid;
    }

    public void setRid() {
        _rid++;
    }

    public List<Response> getAnswers() {
        return _answers;
    }

    public void setAnswers(Response response) { _answers.add(response);
    }

    public void clearAnswers() {
        _answers.clear();
    }

}
