package secforum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AnnouncementTest {

    private Announcement _announcement;

    @Test
    public void validAnnouncement() {
        _announcement = new Announcement("david", "message", new ArrayList<>());
        assertEquals("david", _announcement.getUsername());
        assertEquals("message", _announcement.getMessage());
        assertEquals(0, _announcement.nQuotedAnnouncements());
    }

    @Test
    public void validAnnouncement254() {
        String repeated = new String(new char[254]).replace("\0", "m");
        _announcement = new Announcement("carrasco", repeated, new ArrayList<>());
        assertEquals("carrasco", _announcement.getUsername());
        assertEquals(repeated, _announcement.getMessage());
        assertEquals(0, _announcement.nQuotedAnnouncements());
    }

    @Test
    public void validAnnouncement255() {
        String repeated = new String(new char[255]).replace("\0", "m");
        _announcement = new Announcement( "ricardo", repeated, new ArrayList<>());
        assertEquals(repeated, _announcement.getMessage());
        assertEquals("ricardo", _announcement.getUsername());
        assertEquals(0, _announcement.nQuotedAnnouncements());
    }

    @Test
    public void invalidAnnouncement() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement("david", new String(new char[256]), new ArrayList<>()));
    }

    @Test
    public void invalidAnnouncementNullUsername() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement(null, "", new ArrayList<>()));
    }

    @Test
    public void invalidAnnouncementNullMessage() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement("", null, new ArrayList<>()));
    }

    @Test
    public void invalidAnnouncementNullQuotedAnnouncements() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement("", "", null));
    }
}
