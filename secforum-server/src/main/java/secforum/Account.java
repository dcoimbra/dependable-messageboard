package secforum;

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
}
