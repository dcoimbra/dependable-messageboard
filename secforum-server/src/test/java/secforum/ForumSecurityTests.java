package secforum;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import secforum.response.Response;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ForumSecurityTests {
    private static PublicKey _pubKey1;
    private static PrivateKey _privKey1;
    private static PublicKey _pubKey2;
    private static PublicKey _serverKey;
    private static Integer _nonce;

    private static final String NOT_REGISTERED = "\nRequest error! User is not registered!";
    private static final String SECURITY_ERROR = "\nSecurity error! Message was altered!";
    private static final String QUOTE_ERROR = "\nRequest error! Announcement a does not exist!";

    private static final String POST_RESPONSE = "Successfully uploaded the post.";

    private Forum _forum;
    private String _message;
    private List<String> _quotedAnnouncements;
    private List<String> _wrongQuotedAnnouncements;
    private byte[] _signaturePost;
    private byte[] _signatureAnnouncement;
    private byte[] _signatureRead;
    private byte[] _signatureReadGeneral;
    private int _wts;
    private int _rank;
    private int _rid;

    @BeforeAll
    public static void generate() {
        try {
            _nonce = 1;

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
            _forum = new Forum("server");
            _serverKey = _forum.loadPublicKey();
            _forum.doRegister(_pubKey1);

            _message = "ola";
            _quotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements.add("a");

            _wts = 1;
            _rank = 1;
            _rid = 1;
        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void getNonceSignatureTest() {
        Response res = _forum.getNonce(_pubKey1);;

        try{
            Integer nonce = res.verifyNonce(_forum.loadPublicKey());
            assertEquals(1, nonce);
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
            assertEquals(POST_RESPONSE, res.getResponse());
            assertTrue(res.verify(_serverKey, _nonce + 1, _wts));

            messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _wts + 1, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            res = _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts + 1, _rank, _signaturePost);
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
            assertFalse(res.verify(_serverKey, _nonce + 3, _wts + 1));
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
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
            assertFalse(res.verify(_serverKey, _nonce + 1, _wts));
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postRejectAttackTest() {
        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res = _forum.doPost(_pubKey1, _message, _wrongQuotedAnnouncements, _wts, _rank, _signaturePost);
        assertEquals(QUOTE_ERROR, res.getException().getMessage());
        assertFalse(res.verify(_serverKey, _nonce + 1, _wts));

        messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 2, _wts + 1, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res2 = _forum.doPost(_pubKey1, _message, _quotedAnnouncements, _wts + 1, _rank, _signaturePost);
        assertEquals(POST_RESPONSE, res2.getResponse());
        assertTrue(res2.verify(_serverKey, _nonce + 3, _wts + 1));

        // Attacker gets the invalid request's response and sends it to user when he tries to do another valid request
        assertThrows(IllegalArgumentException.class, () -> res.verify(_serverKey, _nonce + 3, _wts + 1));
    }

//    @Test
//    public void readReplayAttack() {
//        try {
//            byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 0, _nonce);
//            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//            _forum.doRead(_pubKey1, _pubKey1, 0, _signatureRead);
//            Response res = _forum.doRead(_pubKey1, _pubKey1, 0, _signatureRead);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void readIntegrityTest() {
//        try {
//            byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 0, _nonce);
//            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//            Response res = _forum.doRead(_pubKey1, _pubKey1, 404, _signatureRead);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void readRejectAttackTest() {
//        byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 3, _nonce);
//        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        Response res = _forum.doRead(_pubKey1, _pubKey1, 3, _signatureRead);
//
//        messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 0, _nonce + 1);
//        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        _forum.doRead(_pubKey1, _pubKey1, 0, _signatureRead);
//
//        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
//    }

    @Test
    public void postGeneralReplayAttackTest() {
        try {
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);

            Response res = _forum.doPostGeneral(_pubKey1, _message, new ArrayList<>(), _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);
            assertEquals(POST_RESPONSE, res.getResponse());
            assertTrue(res.verify(_serverKey, _nonce + 1, _rid));

            messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid + 1, _wts + 1, _rank);
            announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid + 1, _wts + 1, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);

            res = _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid + 1, _wts + 1, _rank, _signaturePost, _signatureAnnouncement);
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
            assertFalse(res.verify(_serverKey, _nonce + 3, _rid + 1));
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postGeneralIntegrityTest() {
        try {
            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce, _rid, _wts, _rank);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);

            Response res = _forum.doPostGeneral(_pubKey1, "attack", _quotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);
            assertEquals(SECURITY_ERROR, res.getException().getMessage());
            assertFalse(res.verify(_serverKey, _nonce + 1, _wts));
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postGeneralRejectAttackTest() {
        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _rid, _wts, _rank);
        byte[] announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce, _rid, _wts, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
        _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);

        Response res = _forum.doPostGeneral(_pubKey1, _message, _wrongQuotedAnnouncements, _rid, _wts, _rank, _signaturePost, _signatureAnnouncement);
        assertEquals(QUOTE_ERROR, res.getException().getMessage());
        assertFalse(res.verify(_serverKey, _nonce + 1, _wts));

        messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 2, _rid + 1, _wts + 1, _rank);
        announcementBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 2, _rid + 1, _wts + 1, _rank);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
        _signatureAnnouncement = SigningSHA256_RSA.sign(announcementBytesPost, _privKey1);

        Response res2 = _forum.doPostGeneral(_pubKey1, _message, _quotedAnnouncements, _rid + 1, _wts + 1, _rank, _signaturePost, _signatureAnnouncement);
        assertEquals(POST_RESPONSE, res2.getResponse());
        assertTrue(res2.verify(_serverKey, _nonce + 3, _rid + 1));

        // Attacker gets the invalid request's response and sends it to user when he tries to do another valid request
        assertThrows(IllegalArgumentException.class, () -> res.verify(_serverKey, _nonce + 3, _rid + 1));
    }

//    @Test
//    public void readGeneralReplayAttack() {
//        try {
//            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, 0, _nonce);
//            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);
//            _forum.doReadGeneral(_pubKey1, 0, _signatureReadGeneral);
//            Response res = _forum.doReadGeneral(_pubKey1, 0, _signatureReadGeneral);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }

//    @Test
//    public void readGeneralIntegrityTest() {
//        try {
//            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, 0, _nonce);
//            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);
//            Response res = _forum.doReadGeneral(_pubKey1, 404, _signatureReadGeneral);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void readGeneralRejectAttackTest() {
//        byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, 3, _nonce);
//        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        Response res = _forum.doReadGeneral(_pubKey1, 3, _signatureReadGeneral);
//
//        messageBytesRead = Utils.serializeMessage(_pubKey1, 0, _nonce + 1);
//        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        _forum.doReadGeneral(_pubKey1, 0, _signatureReadGeneral);
//
//        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
//    }

    @AfterEach
    public void tearDown() {
        _forum = null;
        _message = null;
        _quotedAnnouncements = null;
        _signaturePost = null;

        for(int i = 0; i < 4; i++) {
            File forum = new File("src/main/resources/forum" + i + ".ser");
            File backup = new File("src/main/resources/forum_backup" + i + ".ser");
            forum.delete();
            backup.delete();
        }
    }
}