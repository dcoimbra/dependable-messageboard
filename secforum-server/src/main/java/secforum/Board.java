package secforum;

import java.util.ArrayList;
import java.util.List;

public class Board {
    private List<Announcement> _announcements;

    public Board() {
        _announcements = new ArrayList<>();
    }

    public void post(String username, String message, List<Announcement> a) {
        Announcement announcement = new Announcement(message, username, a);
        _announcements.add(0, announcement);
    }

    public List<Announcement> read(int number) {

        if (number == 0) {
            return new ArrayList<>(_announcements);
        }

        List<Announcement> result = new ArrayList<>();

        for (int j = 0; j < number; j++) {
            result.add(_announcements.get(j));
        }

        return result;
    }
}
