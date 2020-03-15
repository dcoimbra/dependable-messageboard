package secforum;

import java.util.List;

public class Account {

    private String _username;
    private Board _announcementsBoard;

    public Account(String username) {
        _username = username;
        _announcementsBoard = new Board();
    }

    public String getUsername() {
        return _username;
    }

    public void post(String message,  List<Announcement> a) {
        _announcementsBoard.post(message, _username, a);
    }

    public List<Announcement> read(int number) {
        return _announcementsBoard.read(number);
    }
}
