package secforum;

import mockit.Mocked;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import secforum.response.Response;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.File;
import java.io.IOException;
import java.rmi.Remote;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ForumSecurityTests {
    private Forum _forum;
    private static PublicKey _pubKey1;
    private static PublicKey _pubKey2;
    private static PublicKey _serverKey;
    private static PrivateKey _privKey1;

    private String _message;
    private List<String> _quotedAnnouncements;
    private List<String> _wrongQuotedAnnouncements;
    private int _nAnnouncements;
    private static Integer _nonce;
    private int _wts;
    private int _rank;
    private int _rid;
    @Mocked private Remote _clientStub;

    private byte[] _signaturePost;
    private byte[] _signatureAnnouncement;
    private byte[] _signatureRead;
    private byte[] _signatureReadGeneral;

    private static final int FORUM_ID = 0;
    private static final String INVALID_ID = "vmuiabvauva";
    private static final String POST_RESPONSE = "Successfully uploaded the post.";
    private static final String NOT_REGISTERED = "\nRequest error! User is not registered!";
    private static final String SECURITY_ERROR = "\nSecurity error! Message was altered!";
    private static final String QUOTE_ERROR = "\nRequest error! Announcement " + INVALID_ID + " does not exist!";
    private static final String READ_HIGH = "\nRequest error! Board does not have that many announcements!";

    @BeforeAll
    public static void generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

            SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
            SecureRandom random2 = SecureRandom.getInstance("SHA1PRNG");

            generator.initialize(2048, random1);
            KeyPair pair1 = generator.generateKeyPair();
            _pubKey1 = pair1.getPublic();
            _privKey1 = pair1.getPrivate();

            generator.initialize(2048, random2);
            KeyPair pair2 = generator.generateKeyPair();
            _pubKey2 = pair2.getPublic();
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
    }

    @BeforeEach
    public void setUp() {
        try {
            _forum = new Forum("server", FORUM_ID);
            _forum.doRegister(_pubKey1);
            _serverKey = _forum.loadPublicKey(FORUM_ID);

            _message = "Hello World!";
            _quotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements.add(INVALID_ID);
            _nAnnouncements = 1;
            _nonce = 1;

            _wts = 1;
            _rank = 1;
            _rid = 1;
        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void getNonceSignatureTest() {
        Response res = _forum.getNonce(_pubKey1);

        try{
            Integer nonce = res.verifyNonce(_forum.loadPublicKey(FORUM_ID));
            assertEquals(_nonce, nonce);
        } catch (IllegalArgumentException iae) {
            System.out.println(iae.getMessage());
            fail();
        }
    }

    @Test
    public void getNonceNotRegistered() {
         Response res = _forum.getNonce(_pubKey2);
         assertEquals(NOT_REGISTERED, res.getException().getMessage());
    }

    @Test
    public void postReplayAttackTest() {
        try {
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            Response res = _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);
            assertTrue(res.verify(_serverKey, _nonce + 1, _wts));
            assertEquals(POST_RESPONSE, res.getResponse());

            messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts + 1, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            res = _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts + 1, _rank, _signaturePost);
            assertFalse(res.verify(_serverKey, _nonce + 3, _wts + 1));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postIntegrityTest() {
        try {
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            Response res = _forum.doPost(_pubKey1, "attack", _quotedAnnouncements, _wts, _rank, _signaturePost);
            assertFalse(res.verify(_serverKey, _nonce + 1, _wts));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postRejectAttackTest() {
        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res = _forum.doPost(_pubKey1, _message, _wrongQuotedAnnouncements, _wts, _rank, _signaturePost);
        assertFalse(res.verify(_serverKey, _nonce + 1, _wts));
        assertEquals(QUOTE_ERROR, res.getException().getMessage());

        messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 2, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res2 = _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);
        assertTrue(res2.verify(_serverKey, _nonce + 3, _wts));
        assertEquals(POST_RESPONSE, res2.getResponse());

        // Attacker gets the invalid request's response and sends it to user when he tries to do another valid request
        assertThrows(IllegalArgumentException.class, () -> res.verify(_serverKey, _nonce + 3, _wts));
    }

    @Test
    public void readReplayAttack() {
        try {
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);

            byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, _nAnnouncements, _nonce + 2, _rid, _clientStub);
            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

            Response res = _forum.doRead(_pubKey1, _pubKey1, _nAnnouncements, _rid, _clientStub, _signatureRead);
            assertTrue(res.verify(_serverKey, _nonce + 3, _rid));
            assertEquals(_nAnnouncements, res.getAnnouncements().size());

            messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, _nAnnouncements, _nonce + 2, _rid + 1, _clientStub);
            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

            res = _forum.doRead(_pubKey1, _pubKey1, _nAnnouncements, _rid + 1, _clientStub, _signatureRead);
            assertFalse(res.verify(_serverKey, _nonce + 5, _rid + 1));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readIntegrityTest() {
        try {
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);

            byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, _nAnnouncements, _nonce + 2, _rid, _clientStub);
            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

            Response res = _forum.doRead(_pubKey1, _pubKey1, 404, _rid, _clientStub, _signatureRead);
            assertFalse(res.verify(_serverKey, _nonce + 3, _rid));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readRejectAttackTest() {
        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
        _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);

        byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, _nAnnouncements + 1, _nonce + 2, _rid, _clientStub);
        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        Response res = _forum.doRead(_pubKey1, _pubKey1, _nAnnouncements + 1, _rid, _clientStub, _signatureRead);
        assertFalse(res.verify(_serverKey, _nonce + 3, _rid));
        assertEquals(READ_HIGH, res.getException().getMessage());

        messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, _nAnnouncements, _nonce + 4, _rid + 1, _clientStub);
        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        Response res2 = _forum.doRead(_pubKey1, _pubKey1, _nAnnouncements, _rid + 1, _clientStub, _signatureRead);
        assertTrue(res2.verify(_serverKey, _nonce + 5, _rid + 1));
        assertEquals(_nAnnouncements, res2.getAnnouncements().size());

        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 5, _rid + 1));
    }

    @Test
    public void postGeneralReplayAttackTest() {
        try {
            byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            Response res = _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);
            assertTrue(res.verify(_serverKey, _nonce + 1, _rid));
            assertEquals(POST_RESPONSE, res.getResponse());

            announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts + 1, _rank);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
            messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid + 1, _wts + 1, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            res = _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid + 1, _wts + 1, _rank, _signaturePost, _signatureAnnouncement);
            assertFalse(res.verify(_serverKey, _nonce + 3, _rid + 1));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postGeneralIntegrityTest() {
        try {
            byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            Response res = _forum.doPostGeneral(_pubKey1, "attack", _quotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);
            assertFalse(res.verify(_serverKey, _nonce + 1, _wts));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postGeneralRejectAttackTest() {
        byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _wts, _rank);
        _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _rid, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res = _forum.doPostGeneral(_pubKey1, _message, _wrongQuotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);
        assertFalse(res.verify(_serverKey, _nonce + 1, _wts));
        assertEquals(QUOTE_ERROR, res.getException().getMessage());

        announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 2, _wts, _rank);
        _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
        messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 2, _rid + 1, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res2 = _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid + 1, _wts, _rank, _signaturePost, _signatureAnnouncement);
        assertTrue(res2.verify(_serverKey, _nonce + 3, _rid + 1));
        assertEquals(POST_RESPONSE, res2.getResponse());

        // Attacker gets the invalid request's response and sends it to user when he tries to do another valid request
        assertThrows(IllegalArgumentException.class, () -> res.verify(_serverKey, _nonce + 3, _rid + 1));
    }

    @Test
    public void readGeneralReplayAttack() {
        try {
            byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);

            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, _nAnnouncements, _nonce + 2, _rid + 1);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);

            Response res = _forum.doReadGeneral(_pubKey1, _nAnnouncements, _rid + 1, _signatureReadGeneral);

            assertTrue(res.verify(_serverKey, _nonce + 3, _rid + 1));
            assertEquals(_nAnnouncements, res.getAnnouncements().size());

            messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, _nAnnouncements, _nonce + 2, _rid + 2);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);

            res = _forum.doReadGeneral(_pubKey1, _nAnnouncements, _rid + 2, _signatureReadGeneral);
            assertFalse(res.verify(_serverKey, _nonce + 5, _rid + 2));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readGeneralIntegrityTest() {
        try {
            byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);

            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, _nAnnouncements, _nonce + 2, _rid + 1);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);

            Response res = _forum.doReadGeneral(_pubKey1, 404, _rid + 1, _signatureReadGeneral);
            assertFalse(res.verify(_serverKey, _nonce + 3, _rid + 1));
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readGeneralRejectAttackTest() {
        byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
        _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);
        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
        _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);

        byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _nAnnouncements + 1, _nonce + 2, _rid + 1);
        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        Response res = _forum.doReadGeneral(_pubKey1, _nAnnouncements + 1, _rid + 1, _signatureReadGeneral);
        assertFalse(res.verify(_serverKey, _nonce + 3, _rid + 1));
        assertEquals(READ_HIGH, res.getException().getMessage());

        messageBytesRead = Utils.serializeMessage(_pubKey1, _nAnnouncements, _nonce + 4, _rid + 2);
        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        Response res2 = _forum.doReadGeneral(_pubKey1, _nAnnouncements, _rid + 2, _signatureReadGeneral);
        assertTrue(res2.verify(_serverKey, _nonce + 5, _rid + 2));
        assertEquals(_nAnnouncements, res2.getAnnouncements().size());

        // Attacker gets the invalid request's response and sends it to user when he tries to do another valid request
        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 5, _rid + 2));
    }

    @AfterEach
    public void tearDown() {
        _rid = -1;
        _rank = -1;
        _wts = -1;

        _nAnnouncements = -1;
        _wrongQuotedAnnouncements = new ArrayList<>();
        _quotedAnnouncements = null;
        _message = null;

        _serverKey = null;
        _forum = null;

        _signatureReadGeneral = null;
        _signatureRead = null;
        _signatureAnnouncement = null;
        _signaturePost = null;

        File forum = new File("src/main/resources/forum" + FORUM_ID + ".ser");
        File backup = new File("src/main/resources/forum_backup" + FORUM_ID + ".ser");
        forum.delete();
        backup.delete();
    }
}