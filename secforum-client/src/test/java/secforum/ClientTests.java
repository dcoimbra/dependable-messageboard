package secforum;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import security.Utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ClientTests {
    private static Client _client;
    private static List<Thread> _threads;
    private static String _postMessage;
    private static String _readMessage;
    private static List<String> _quotedAnnouncements;
    private static PublicKey _publicKey;
    private static int _nAnnouncements;

    private static final String ID = "1";
    private static final String INVALID_ID = "vmuiabvauva";
    private static final String STATE_PATH = "../secforum-server/src/main/resources/";
    private final String WRITE_RESPONSE = "Post verified!";
    private final String READ_RESPONSE = "Got 1 announcement(s)!";

    @BeforeAll
    static void setup() {

        try {
            ByteArrayInputStream in = new ByteArrayInputStream(("client" + ID).getBytes());
            System.setIn(in);

            _client = new Client(ID);
            _threads = new ArrayList<>();

            _client.register(_threads);
            _threads = new ArrayList<>();

            _postMessage = "Hello World!";
            _readMessage = "Goodbye World!";
            _quotedAnnouncements = new ArrayList<>();
            _publicKey = Utils.loadPublicKey(ID);
            _nAnnouncements = 1;
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void validPost() {
        try {
            String response = _client.post(_threads, _postMessage, _quotedAnnouncements);
            assertEquals(WRITE_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void invalidPostMessageTooLong() {
        String invalidMessage = new String(new char[256]);
        assertThrows(IllegalArgumentException.class,
                () -> _client.post(_threads, invalidMessage, _quotedAnnouncements));
    }

    @Test
    void invalidPostQuotedAnnouncementDoesNotExist() {
        _quotedAnnouncements.add(INVALID_ID);
        assertThrows(IllegalArgumentException.class,
                () -> _client.post(_threads, _postMessage, _quotedAnnouncements));
    }

    @Test
    void validRead() {
        try {
            _client.post(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            String response = _client.read(_threads, _publicKey, _nAnnouncements);
            assertEquals(READ_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void invalidReadPublicKeyDoesNotExist() {
        try {
            _client.post(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            assertThrows(IllegalArgumentException.class,
                    () ->_client.read(_threads, Utils.loadPublicKey("2"), _nAnnouncements));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void invalidReadNAnnouncementsTooHigh() {
        try {
            _client.post(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            assertThrows(IllegalArgumentException.class,
                    () ->_client.read(_threads, _publicKey, 1000));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void invalidReadNAnnouncementsTooLow() {
        try {
            _client.post(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            assertThrows(IllegalArgumentException.class,
                    () ->_client.read(_threads, _publicKey, -1));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void validPostGeneral() {
        try {
            String response = _client.postGeneral(_threads, _postMessage, _quotedAnnouncements);
            assertEquals(WRITE_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void invalidPostGeneralMessageTooLong() {
        String invalidMessage = new String(new char[256]);
        assertThrows(IllegalArgumentException.class,
                () -> _client.postGeneral(_threads, invalidMessage, _quotedAnnouncements));
    }

    @Test
    void invalidPostGeneralQuotedAnnouncementDoesNotExist() {
        _quotedAnnouncements.add(INVALID_ID);
        assertThrows(IllegalArgumentException.class,
                () -> _client.postGeneral(_threads, _postMessage, _quotedAnnouncements));
    }

    @Test
    void validReadGeneral() {
        try {
            _client.postGeneral(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            String response = _client.readGeneral(_threads, _nAnnouncements);
            assertEquals(READ_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void invalidReadGeneralNAnnouncementsTooHigh() {
        try {
            _client.postGeneral(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            assertThrows(IllegalArgumentException.class,
                    () ->_client.readGeneral(_threads, 1000));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void invalidReadGeneralNAnnouncementsTooLow() {
        try {
            _client.postGeneral(_threads, _readMessage, _quotedAnnouncements);
            _threads = new ArrayList<>();

            assertThrows(IllegalArgumentException.class,
                    () ->_client.readGeneral(_threads, -1));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @AfterEach
    void reset() {
        _threads = new ArrayList<>();
        _quotedAnnouncements = new ArrayList<>();
    }

    @AfterAll
    static void tearDown() {
        _nAnnouncements = -1;
        _publicKey = null;
        _quotedAnnouncements = null;
        _readMessage = null;
        _postMessage = null;
        _threads = null;
        _client = null;

        for(int i = 0; i < 4; i++) {
            File forum = new File(STATE_PATH + "forum" + i + ".ser");
            File backup = new File(STATE_PATH + "forum_backup" + i + ".ser");
            forum.delete();
            backup.delete();
        }
    }
}
