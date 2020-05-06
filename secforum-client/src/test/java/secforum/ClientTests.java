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
    private static String _message;
    private static List<String> _quotedAnnouncements;
    private static PublicKey _publicKey;
    private static int _nAnnouncements;

    private final String WRITE_RESPONSE = "Post verified!";
    private final String READ_RESPONSE = "Got 1 announcement(s)!";
    private static final String ID = "1";
    private static final String STATE_PATH = "../secforum-server/src/main/resources/";

    @BeforeAll
    static void setup() {

        try {
            ByteArrayInputStream in = new ByteArrayInputStream(("client" + ID).getBytes());
            System.setIn(in);

            _client = new Client(ID);
            _threads = new ArrayList<>();
            _client.register(_threads);
            _threads = new ArrayList<>();

            _message = "Hello World!";
            _quotedAnnouncements = new ArrayList<>();
            _publicKey = Utils.loadPublicKey("1");
            _nAnnouncements = 0;
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void validPost() {
        try {
            String response = _client.post(_threads, _message, _quotedAnnouncements);
            assertEquals(WRITE_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void validRead() {
        try {
            String response = _client.read(_threads, _publicKey, _nAnnouncements);
            assertEquals(READ_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void validPostGeneral() {
        try {
            String response = _client.postGeneral(_threads, _message, _quotedAnnouncements);
            assertEquals(WRITE_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    void validReadGeneral() {
        try {
            String response = _client.readGeneral(_threads, _nAnnouncements);
            assertEquals(READ_RESPONSE, response);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @AfterEach
    void reset() {
        _threads = new ArrayList<>();
    }

    @AfterAll
    static void tearDown() {
        _message = null;
        _quotedAnnouncements = null;

        for(int i = 0; i < 4; i++) {
            File forum = new File(STATE_PATH + "forum" + i + ".ser");
            File backup = new File(STATE_PATH + "forum_backup" + i + ".ser");
            forum.delete();
            backup.delete();
        }
    }
}
