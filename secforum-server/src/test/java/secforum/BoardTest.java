package secforum;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class BoardTest {
    private Board _board;

    @BeforeEach
    public void setup() {
        _board = new Board();
    }

    @Test
    public void constructorTest() {
        Board tBoard = new Board();
        assertEquals(0, tBoard.nAnnouncements());
    }

    @Test
    public void postValidAnnouncement() {
        _board.post("david", "test1", new ArrayList<>());
        assertEquals(1, _board.nAnnouncements());

        List<Announcement> mostRecent = _board.read(1);

        Announcement a = mostRecent.get(0);

        assertEquals("david", a.getUsername());
        assertEquals("test1", a.getMessage());
        assertEquals(0, a.nQuotedAnnouncements());
    }

    @Test
    public void postTwoAnnouncements() {
        _board.post("david", "test1", new ArrayList<>());
        _board.post("carrasco", "test2", new ArrayList<>());
        assertEquals(2, _board.nAnnouncements());

        List<Announcement> mostRecent = _board.read(2);

        Announcement a1 = mostRecent.get(0);
        assertEquals("carrasco", a1.getUsername());
        assertEquals("test2", a1.getMessage());
        assertEquals(0, a1.nQuotedAnnouncements());

        Announcement a2 = mostRecent.get(1);
        assertEquals("david", a2.getUsername());
        assertEquals("test1", a2.getMessage());
        assertEquals(0, a2.nQuotedAnnouncements());
    }

    @Test
    public void postInvalidAnnouncement() {
        assertThrows(IllegalArgumentException.class,
                () ->_board.post("carrasco", new String(new char[256]), new ArrayList<>()));
    }

    @Test
    public void readEmptyBoard() {
        List<Announcement> empty = _board.read(0);
        assertEquals(0, empty.size());
    }

    @Test
    public void readEmptyBoardNonZero() {
        assertThrows(IllegalArgumentException.class,
                () ->_board.read(1));
    }

    @Test
    public void readInputTooBig() {
        _board.post("david", "test1", new ArrayList<>());
        _board.post("carrasco", "test2", new ArrayList<>());
        _board.post("ricardo", "test3", new ArrayList<>());

        assertThrows(IllegalArgumentException.class,
                () ->_board.read(4));
    }

    @Test
    public void readAllAnnouncements() {
        _board.post("david", "test1", new ArrayList<>());
        _board.post("carrasco", "test2", new ArrayList<>());
        _board.post("ricardo", "test3", new ArrayList<>());

        List<Announcement> all = _board.read(0);
        assertEquals(3, all.size());
    }

    @Test
    public void readTwoMostRecentAnnouncements() {
        _board.post("david", "test1", new ArrayList<>());
        _board.post("carrasco", "test2", new ArrayList<>());
        _board.post("ricardo", "test3", new ArrayList<>());

        List<Announcement> mostRecent = _board.read(2);
        assertEquals(2, mostRecent.size());
    }

    @AfterEach
    public void tearDown() {
        _board = null;
        assertNull(_board);
    }
}
