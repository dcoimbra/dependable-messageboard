package secforum;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AnnouncementTest {

    private Announcement _announcement;

    @Test
    public void validAnnouncement() {
        _announcement = new Announcement("message", "david", new ArrayList<>());
        assertEquals("message", _announcement.getMessage());
        assertEquals("david", _announcement.getUsername());
    }

    @Test
    public void validAnnouncement254() {
        String repeated = new String(new char[254]).replace("\0", "m");
        _announcement = new Announcement(repeated, "david", new ArrayList<>());
        assertEquals(repeated, _announcement.getMessage());
        assertEquals("david", _announcement.getUsername());
    }

    @Test
    public void validAnnouncement255() {
        String repeated = new String(new char[255]).replace("\0", "m");
        _announcement = new Announcement(repeated, "david", new ArrayList<>());
        assertEquals(repeated, _announcement.getMessage());
        assertEquals("david", _announcement.getUsername());
    }

    @Test
    public void invalidAnnouncement() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement(new String(new char[256]), "david", new ArrayList<>()));
    }
}
