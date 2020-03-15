package secforum;

import java.util.ArrayList;
import java.util.List;

public class Board {
    private List<Announcement> _announcements;

    public Board() {
        _announcements = new ArrayList<>();
    }

    public void postAnnouncement(Announcement announcement) {
        _announcements.add(announcement);
    }
}
