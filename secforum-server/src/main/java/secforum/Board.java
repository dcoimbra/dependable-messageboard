package secforum;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Board implements Serializable {
    private List<Announcement> _announcements;

    public Board() {
        _announcements = new ArrayList<>();
    }

    public void post(String username, String message, List<Announcement> a) throws IllegalArgumentException {

        Announcement announcement = new Announcement(username, message, a);
        _announcements.add(0, announcement);
    }

    public List<Announcement> read(int number) throws IllegalArgumentException {

        if (number > _announcements.size()) {
            throw new IllegalArgumentException();
        }

        if (number == 0) {
            return new ArrayList<>(_announcements);
        }

        List<Announcement> result = new ArrayList<>();

        for (int j = 0; j < number; j++) {
            result.add(_announcements.get(j));
        }


        return result;
    }

    public int nAnnouncements() {
        return _announcements.size();
    }
}
