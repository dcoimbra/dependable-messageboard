package secforum;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.File;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ForumTests {
    private Forum _forum;
    private static PublicKey _pubKey1;
    private static PublicKey _pubKey2;
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

    private byte[] _signaturePost;
    private byte[] _signatureRead;
    private byte[] _signatureReadGeneral;


    private byte[] _signaturePostInvalid;
    private byte[] _signatureReadTooHigh;
    private byte[] _signatureReadNegative;
    private byte[] _signatureReadGeneralTooHigh;
    private byte[] _signatureReadGeneralNegative;

//    @BeforeAll
//    public static void generate() {
//       try {
//           KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//
//           SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
//           SecureRandom random2 = SecureRandom.getInstance("SHA1PRNG");
//
//           generator.initialize(2048, random1);
//
//           KeyPair pair1 = generator.generateKeyPair();
//           _pubKey1 = pair1.getPublic();
//           _privKey1 = pair1.getPrivate();
//
//           generator.initialize(2048, random2);
//
//           KeyPair pair2 = generator.generateKeyPair();
//           _pubKey2 = pair2.getPublic();
//           _privKey2 = pair2.getPrivate();
//       } catch (NoSuchAlgorithmException e) {
//           fail();
//       }
//    }
//
//    @BeforeEach
//    public void setUp() {
//        try {
//            _forum = new Forum("server");
//
//            _forum.register(_pubKey1);
//            byte[] messageBytes;
//
//            _message = "ola";
//            _quotedAnnouncements = new ArrayList<>();
//            _wrongQuotedAnnouncements = new ArrayList<>();
//            _wrongQuotedAnnouncements.add("aahrevbbver");
//            _read = 1;
//            _negative = -1;
//            _high = 2;
//            _nonce = 1;
//            _counter = _nonce - 1;
//
//            messageBytes = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _forum.getAccounts().get(_pubKey1).getNonce());
//            _signaturePost = SigningSHA256_RSA.sign(messageBytes, _privKey1);
//
//            messageBytes = Utils.serializeMessage(_pubKey2, _pubKey1, _read, _nonce);
//            _signatureRead = SigningSHA256_RSA.sign(messageBytes, _privKey2);
//
//            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey2, _read, _nonce);
//            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey2);
//
//            messageBytes = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _forum.getAccounts().get(_pubKey1).getNonce());
//            _signaturePostInvalid = SigningSHA256_RSA.sign(messageBytes, _privKey1);
//
//            messageBytes = Utils.serializeMessage(_pubKey2, _pubKey1, _high, _nonce);
//            _signatureReadTooHigh = SigningSHA256_RSA.sign(messageBytes, _privKey2);
//
//            messageBytes = Utils.serializeMessage(_pubKey2, _high, _nonce);
//            _signatureReadGeneralTooHigh = SigningSHA256_RSA.sign(messageBytes, _privKey2);
//
//            messageBytes = Utils.serializeMessage(_pubKey2, _pubKey1, _negative, _nonce);
//            _signatureReadNegative = SigningSHA256_RSA.sign(messageBytes, _privKey2);
//
//            messageBytes = Utils.serializeMessage(_pubKey2, _negative, _nonce);
//            _signatureReadGeneralNegative = SigningSHA256_RSA.sign(messageBytes, _privKey2);
//        } catch (IOException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void registerValidTest() {
//        Response res = _forum.register(_pubKey2);
//        assertNull(res.getAnnouncements());
//        assertNull(res.getException());
//        assertEquals("Registered successfully.", res.getResponse());
//    }
//
//    @Test
//    public void registerAlreadyRegistered() {
//        Response res = _forum.register(_pubKey1);
//        assertEquals("Your public key is already registered.", res.getException().getMessage());
//    }
//
//    @Test
//    public void postValidTest() {
//        Response res = _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//        assertNull(res.getAnnouncements());
//        assertNull(res.getException());
//        assertEquals("Successfully uploaded the post.", res.getResponse());
//    }
//
//    @Test
//    public void invalidPostNotRegistered() {
//        Response res = _forum.post(_pubKey2, _message, _quotedAnnouncements, _signaturePost);
//        assertEquals("Your public key is not registered.", res.getException().getMessage());
//    }
//
//    @Test
//    public void invalidPostAnnouncementDoesNotExist() {
//        Response res = _forum.post(_pubKey1, _message, _wrongQuotedAnnouncements, _signaturePostInvalid);
//        assertEquals("Announcement a does not exist", res.getException().getMessage());
//    }
//
//    @Test
//    public void postGeneralValidTest() {
//        Response res = _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//        assertNull(res.getAnnouncements());
//        assertNull(res.getException());
//        assertEquals("Successfully uploaded the post.", res.getResponse());
//    }
//
//    @Test
//    public void invalidPostGeneralNotRegistered() {
//        Response res = _forum.postGeneral(_pubKey2, _message, _quotedAnnouncements, _signaturePost);
//        assertEquals("Your public key is not registered.", res.getException().getMessage());
//    }
//
//    @Test
//    public void invalidPostGeneralAnnouncementDoesNotExist() {
//        Response res = _forum.postGeneral(_pubKey1, _message, _wrongQuotedAnnouncements, _signaturePostInvalid);
//        assertEquals("Announcement a does not exist", res.getException().getMessage());
//    }
//
//    @Test
//    public void validRead() {
//        try {
//            _forum.register(_pubKey2);
//            _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//            Response res = _forum.read(_pubKey2, _pubKey1, _read, _signatureRead);
//
//            assertNull(res.getResponse());
//            assertNull(res.getException());
//
//            Announcement a = new Announcement(_pubKey1, _message, new ArrayList<>(), _nonce - 1,_signaturePost, _counter);
//            Announcement received = res.getAnnouncements().get(0);
//
//            assertEquals(a.getId(), received.getId());
//            assertEquals(a.getPubKey(), received.getPubKey());
//            assertEquals(a.nQuotedAnnouncements(), received.nQuotedAnnouncements());
//            assertEquals(a.getMessage(), received.getMessage());
//        } catch (RemoteException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void invalidReadNegative() {
//        _forum.register(_pubKey2);
//        _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//
//        Response res = _forum.read(_pubKey2, _pubKey1, _negative, _signatureReadNegative);
//        assertEquals("The number of announcements to read must not be less than zero", res.getException().getMessage());
//    }
//
//    @Test
//    public void invalidReadTooHigh() {
//        _forum.register(_pubKey2);
//        _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//
//        Response res = _forum.read(_pubKey2, _pubKey1, _high, _signatureReadTooHigh);
//        assertEquals("Board does not have that many announcements", res.getException().getMessage());
//    }
//
//    @Test
//    public void validReadGeneral() {
//        try {
//            _forum.register(_pubKey2);
//            _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//            Response res = _forum.readGeneral(_pubKey2, _read, _signatureReadGeneral);
//
//            assertNull(res.getResponse());
//            assertNull(res.getException());
//
//            Announcement a = new Announcement(_pubKey1, _message, new ArrayList<>(), _nonce - 1,_signaturePost, _counter);
//            Announcement received = res.getAnnouncements().get(0);
//
//            assertEquals(a.getId(), received.getId());
//            assertEquals(a.getPubKey(), received.getPubKey());
//            assertEquals(a.nQuotedAnnouncements(), received.nQuotedAnnouncements());
//            assertEquals(a.getMessage(), received.getMessage());
//
//        } catch (RemoteException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void invalidReadGeneralNegative() {
//        _forum.register(_pubKey2);
//        _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//
//        Response res = _forum.readGeneral(_pubKey2, _negative, _signatureReadGeneralNegative);
//        assertEquals("The number of announcements to read must not be less than zero", res.getException().getMessage());
//    }
//
//    @Test
//    public void invalidReadGeneralTooHigh() {
//        _forum.register(_pubKey2);
//        _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//
//        Response res = _forum.readGeneral(_pubKey2, _high, _signatureReadGeneralTooHigh);
//        assertEquals("Board does not have that many announcements", res.getException().getMessage());
//    }
//
//    @AfterEach
//    public void tearDown() {
//        _forum = null;
//        _message = null;
//        _quotedAnnouncements = null;
//        _signaturePost = null;
//
//        for(int i = 0; i < 4; i++) {
//        File forum = new File("src/main/resources/forum" + i + ".ser");
//        File backup = new File("src/main/resources/forum_backup" + i + ".ser");
//        forum.delete();
//        backup.delete();
//        }
//    }
}
