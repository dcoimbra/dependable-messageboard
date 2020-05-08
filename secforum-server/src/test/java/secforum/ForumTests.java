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
import java.rmi.RemoteException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ForumTests {
    private Forum _forum;
    private static PublicKey _pubKey1;
    private static PublicKey _pubKey2;
    private static PublicKey _serverKey;
    private static PrivateKey _privKey1;
    private static PrivateKey _privKey2;

    private String _message;
    private List<String> _quotedAnnouncements;
    private List<String> _wrongQuotedAnnouncements;
    private int _read;
    private int _negative;
    private int _high;
    private int _nonce;
    private int _counter;
    private int _wts;
    private int _rank;
    private int _rid;
    @Mocked private Remote _clientStub;

    private byte[] _signaturePost;
    private byte[] _signatureRead;
    private byte[] _signaturePostGeneral;
    private byte[] _signatureReadGeneral;
    private byte[] _signaturePostInvalid;
    private byte[] _signatureReadTooHigh;
    private byte[] _signatureReadNegative;
    private byte[] _signaturePostGeneralInvalid;
    private byte[] _signatureReadGeneralTooHigh;
    private byte[] _signatureReadGeneralNegative;

    private static final int FORUM_ID = 0;
    private static final String INVALID_ID = "vmuiabvauva";
    private static final String POST_RESPONSE = "Successfully uploaded the post.";
    private static final String NOT_REGISTERED = "\nRequest error! User is not registered!";
    private static final String QUOTE_ERROR = "\nRequest error! Announcement " + INVALID_ID + " does not exist!";
    private static final String READ_NEGATIVE = "\nRequest error! Number of announcements cannot be negative!";
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
           _privKey2 = pair2.getPrivate();
       } catch (NoSuchAlgorithmException e) {
           fail();
       }
    }

    @BeforeEach
    public void setUp() {
        try {
            _forum = new Forum("server" + FORUM_ID, FORUM_ID);
            _forum.doRegister(_pubKey1);
            _serverKey = _forum.loadPublicKey(FORUM_ID);
            byte[] messageBytes;

            _message = "Hello World!";
            _quotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements.add(INVALID_ID);
            _read = 1;
            _negative = -1;
            _high = 2;
            _nonce = 1;
            _counter = 0;

            _wts = 1;
            _rank = 1;
            _rid = 1;

            messageBytes = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytes, _privKey1);

            messageBytes = Utils.serializeMessage(_pubKey2, _pubKey1, _read, _nonce, _rid, _clientStub);
            _signatureRead = SigningSHA256_RSA.sign(messageBytes, _privKey2);

            messageBytes = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePostGeneral = SigningSHA256_RSA.sign(messageBytes, _privKey1);

            messageBytes = Utils.serializeMessage(_pubKey2, _read, _nonce, _rid);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytes, _privKey2);

            messageBytes = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _wts, _rank);
            _signaturePostInvalid = SigningSHA256_RSA.sign(messageBytes, _privKey1);

            messageBytes = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePostGeneralInvalid = SigningSHA256_RSA.sign(messageBytes, _privKey1);

            messageBytes = Utils.serializeMessage(_pubKey2, _pubKey1, _high, _nonce, _rid, _clientStub);
            _signatureReadTooHigh = SigningSHA256_RSA.sign(messageBytes, _privKey2);

            messageBytes = Utils.serializeMessage(_pubKey2, _high, _nonce, _rid);
            _signatureReadGeneralTooHigh = SigningSHA256_RSA.sign(messageBytes, _privKey2);

            messageBytes = Utils.serializeMessage(_pubKey2, _pubKey1, _negative, _nonce, _rid, _clientStub);
            _signatureReadNegative = SigningSHA256_RSA.sign(messageBytes, _privKey2);

            messageBytes = Utils.serializeMessage(_pubKey2, _negative, _nonce, _rid);
            _signatureReadGeneralNegative = SigningSHA256_RSA.sign(messageBytes, _privKey2);
        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void registerValidTest() {
        Response res = _forum.doRegister(_pubKey2);
        assertNull(res.getAnnouncements());
        assertNull(res.getException());
        assertEquals("Registered successfully.", res.getResponse());
    }

    @Test
    public void registerAlreadyRegistered() {
        Response res = _forum.doRegister(_pubKey1);
        assertEquals("\nRequest error! User is already registered!", res.getException().getMessage());
    }

    @Test
    public void postValidTest() {
        Response res = _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);
        assertNull(res.getAnnouncements());
        assertNull(res.getException());
        assertEquals(POST_RESPONSE, res.getResponse());
    }

    @Test
    public void invalidPostNotRegistered() {
        Response res = _forum.doPost(_pubKey2, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);
        assertEquals(NOT_REGISTERED, res.getException().getMessage());
    }

    @Test
    public void invalidPostAnnouncementDoesNotExist() {
        Response res = _forum.doPost(_pubKey1, _message, _wrongQuotedAnnouncements, _wts, _rank, _signaturePostInvalid);
        assertEquals(QUOTE_ERROR, res.getException().getMessage());
    }

    @Test
    public void postGeneralValidTest() {
        Response res = _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePostGeneral, _signaturePost);
        assertNull(res.getAnnouncements());
        assertNull(res.getException());
        assertEquals(POST_RESPONSE, res.getResponse());
    }

    @Test
    public void invalidPostGeneralNotRegistered() {
        Response res = _forum.doPostGeneral(_pubKey2, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePostGeneral, _signaturePost);
        assertEquals(NOT_REGISTERED, res.getException().getMessage());
    }

    @Test
    public void invalidPostGeneralAnnouncementDoesNotExist() {
        Response res = _forum.doPostGeneral(_pubKey1, _message, _wrongQuotedAnnouncements, _rid, _wts, _rank, _signaturePostGeneralInvalid, _signaturePostInvalid);
        assertEquals(QUOTE_ERROR, res.getException().getMessage());
    }

    @Test
    public void validRead() {
        try {
            _forum.doRegister(_pubKey2);
            _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);
            Response res = _forum.doRead(_pubKey2, _pubKey1, _read, _rid, _clientStub, _signatureRead);

            assertNull(res.getResponse());
            assertNull(res.getException());

            Announcement a = new Announcement(_pubKey1, _message, new ArrayList<>(), _nonce - 1, _signaturePost, _counter, _wts, _rank);
            Announcement received = res.getAnnouncements().get(0);

            assertEquals(a.getId(), received.getId());
            assertEquals(a.getPubKey(), received.getPubKey());
            assertEquals(a.nQuotedAnnouncements(), received.nQuotedAnnouncements());
            assertEquals(a.getMessage(), received.getMessage());
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidReadNegative() {
        _forum.doRegister(_pubKey2);
        _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);

        Response res = _forum.doRead(_pubKey2, _pubKey1, _negative, _rid, _clientStub, _signatureReadNegative);
        assertEquals(READ_NEGATIVE, res.getException().getMessage());
    }

    @Test
    public void invalidReadTooHigh() {
        _forum.doRegister(_pubKey2);
        _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts, _rank, _signaturePost);

        Response res = _forum.doRead(_pubKey2, _pubKey1, _high, _rid, _clientStub, _signatureReadTooHigh);
        assertEquals(READ_HIGH, res.getException().getMessage());
    }

    @Test
    public void validReadGeneral() {
        try {
            _forum.doRegister(_pubKey2);
            _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePostGeneral, _signaturePost);
            Response res = _forum.doReadGeneral(_pubKey2, _read, _rid, _signatureReadGeneral);

            assertNull(res.getResponse());
            assertNull(res.getException());

            Announcement a = new Announcement(_pubKey1, _message, new ArrayList<>(), _nonce - 1, _signaturePost, _counter, _wts, _rank);
            Announcement received = res.getAnnouncements().get(0);

            assertEquals(a.getId(), received.getId());
            assertEquals(a.getPubKey(), received.getPubKey());
            assertEquals(a.nQuotedAnnouncements(), received.nQuotedAnnouncements());
            assertEquals(a.getMessage(), received.getMessage());

        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidReadGeneralNegative() {
        _forum.doRegister(_pubKey2);
        _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePostGeneral, _signaturePost);

        Response res = _forum.doReadGeneral(_pubKey2, _negative, _rid, _signatureReadGeneralNegative);
        assertEquals(READ_NEGATIVE, res.getException().getMessage());
    }

    @Test
    public void invalidReadGeneralTooHigh() {
        _forum.doRegister(_pubKey2);
        _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid, _wts, _rank, _signaturePostGeneral, _signaturePost);

        Response res = _forum.doReadGeneral(_pubKey2, _high, _rid, _signatureReadGeneralTooHigh);
        assertEquals(READ_HIGH, res.getException().getMessage());
    }

    @AfterEach
    public void tearDown() {
        _forum = null;
        _message = null;
        _quotedAnnouncements = null;
        _signaturePost = null;

        File forum = new File("src/main/resources/forum" + FORUM_ID + ".ser");
        File backup = new File("src/main/resources/forum_backup" + FORUM_ID + ".ser");
        forum.delete();
        backup.delete();
    }
}
