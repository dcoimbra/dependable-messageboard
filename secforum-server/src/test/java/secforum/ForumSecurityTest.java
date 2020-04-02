package secforum;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ForumSecurityTest {
    private Forum _forum;
    private static PublicKey _pubKey1;
    private static PublicKey _pubKey2;
    private String _message;
    private List<String> _quotedAnnouncements;
    private List<String> _wrongQuotedAnnouncements;
    private LocalDateTime _timestamp;
    private byte[] _signaturePost;
    private byte[] _signatureRead;
    private static PrivateKey _privKey1;
    private static PrivateKey _privKey2;
    private byte[] _signatureReadGeneral;
    private static Integer _nonce;

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
            _privKey2 = pair2.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
    }

    @BeforeEach
    public void setUp() {
        try {
            _forum = new Forum("server");

            _forum.register(_pubKey1);

            _message = "ola";
            _quotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements = new ArrayList<>();
            _wrongQuotedAnnouncements.add("a");
            _timestamp = LocalDateTime.now();

        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void getNonceSignatureTest() {
        Response res = _forum.getNonce(_pubKey1);

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
         assertEquals("This public key is not registered.", res.getException().getMessage());
    }

    @Test
    public void postReplayAttackTest() {
        List<Object> toSerializePost = new ArrayList<>();
        toSerializePost.add(_pubKey1);
        toSerializePost.add(_message);
        toSerializePost.add(_quotedAnnouncements);
        toSerializePost.add(_timestamp);
        toSerializePost.add(_nonce);

        try {
            byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            _forum.post(_pubKey1, _message, new ArrayList<>(), _timestamp, _signaturePost);
            Response res = _forum.post(_pubKey1, _message, new ArrayList<>(), _timestamp, _signaturePost);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postGeneralReplayAttackTest() {
        List<Object> toSerializePost = new ArrayList<>();
        toSerializePost.add(_pubKey1);
        toSerializePost.add(_message);
        toSerializePost.add(_quotedAnnouncements);
        toSerializePost.add(_timestamp);
        toSerializePost.add(_nonce);

        try {
            byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            _forum.postGeneral(_pubKey1, _message, new ArrayList<>(), _timestamp, _signaturePost);
            Response res = _forum.postGeneral(_pubKey1, _message, new ArrayList<>(), _timestamp, _signaturePost);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }



    @Test
    public void readReplayAttack() {
        List<Object> toSerializeRead = new ArrayList<>();
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(0);
        toSerializeRead.add(_nonce);

        try {
            byte[] messageBytesRead = Utils.serializeMessage(toSerializeRead);
            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

            _forum.read(_pubKey1, _pubKey1, 0, _signatureRead);
            Response res = _forum.read(_pubKey1, _pubKey1, 0, _signatureRead);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readGeneralReplayAttack() {
        List<Object> toSerializeReadGeneral = new ArrayList<>();
        toSerializeReadGeneral.add(_pubKey1);
        toSerializeReadGeneral.add(0);
        toSerializeReadGeneral.add(_nonce);

        try {
            byte[] messageBytesReadGeneral = Utils.serializeMessage(toSerializeReadGeneral);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);
            _forum.readGeneral(_pubKey1, 0, _signatureReadGeneral);
            Response res = _forum.readGeneral(_pubKey1, 0, _signatureReadGeneral);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postIntegrityTest() {
        List<Object> toSerializePost = new ArrayList<>();
        toSerializePost.add(_pubKey1);
        toSerializePost.add(_message);
        toSerializePost.add(_quotedAnnouncements);
        toSerializePost.add(_timestamp);
        toSerializePost.add(_nonce);

        try {
            byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            Response res = _forum.post(_pubKey1, "attack", new ArrayList<>(), _timestamp, _signaturePost);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postGeneralIntegrityTest() {
        List<Object> toSerializePost = new ArrayList<>();
        toSerializePost.add(_pubKey1);
        toSerializePost.add(_message);
        toSerializePost.add(_quotedAnnouncements);
        toSerializePost.add(_timestamp);
        toSerializePost.add(_nonce);

        try {
            byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
            Response res = _forum.postGeneral(_pubKey1, "attack", new ArrayList<>(), _timestamp, _signaturePost);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readIntegrityTest() {
        List<Object> toSerializeRead = new ArrayList<>();
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(0);
        toSerializeRead.add(_nonce);

        try {
            byte[] messageBytesRead = Utils.serializeMessage(toSerializeRead);
            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
            Response res = _forum.read(_pubKey1, _pubKey1, 404, _signatureRead);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void readGeneralIntegrityTest() {
        List<Object> toSerializeReadGeneral = new ArrayList<>();
        toSerializeReadGeneral.add(_pubKey1);
        toSerializeReadGeneral.add(0);
        toSerializeReadGeneral.add(_nonce);

        try {
            byte[] messageBytesReadGeneral = Utils.serializeMessage(toSerializeReadGeneral);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);
            Response res = _forum.readGeneral(_pubKey1, 404, _signatureReadGeneral);

            assertEquals("Security error. Message was altered.", res.getException().getMessage());
        } catch (IllegalArgumentException e) {
            fail();
        }
    }

    @Test
    public void postRejectAttackTest() {
        List<Object> toSerializePost = new ArrayList<>();
        toSerializePost.add(_pubKey1);
        toSerializePost.add(_message);
        toSerializePost.add(_wrongQuotedAnnouncements);
        toSerializePost.add(_timestamp);
        toSerializePost.add(_nonce);

        List<Object> toSerializePost2 = new ArrayList<>();
        toSerializePost2.add(_pubKey1);
        toSerializePost2.add(_message);
        toSerializePost2.add(_quotedAnnouncements);
        toSerializePost2.add(_timestamp);
        toSerializePost2.add(_nonce + 1);

        byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res = _forum.post(_pubKey1, _message, _wrongQuotedAnnouncements, _timestamp, _signaturePost);

        messageBytesPost = Utils.serializeMessage(toSerializePost2);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        _forum.post(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);

        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
    }

    @Test
    public void postGeneralRejectAttackTest() {
        List<Object> toSerializePost = new ArrayList<>();
        toSerializePost.add(_pubKey1);
        toSerializePost.add(_message);
        toSerializePost.add(_wrongQuotedAnnouncements);
        toSerializePost.add(_timestamp);
        toSerializePost.add(_nonce);

        List<Object> toSerializePost2 = new ArrayList<>();
        toSerializePost2.add(_pubKey1);
        toSerializePost2.add(_message);
        toSerializePost2.add(_quotedAnnouncements);
        toSerializePost2.add(_timestamp);
        toSerializePost2.add(_nonce + 1);

        byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        Response res = _forum.postGeneral(_pubKey1, _message, _wrongQuotedAnnouncements, _timestamp, _signaturePost);

        messageBytesPost = Utils.serializeMessage(toSerializePost2);
        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

        _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);

        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
    }

    @Test
    public void readRejectAttackTest() {
        List<Object> toSerializeRead = new ArrayList<>();
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(3);
        toSerializeRead.add(_nonce);

        List<Object> toSerializeRead2 = new ArrayList<>();
        toSerializeRead2.add(_pubKey1);
        toSerializeRead2.add(_pubKey1);
        toSerializeRead2.add(0);
        toSerializeRead2.add(_nonce + 1);

        byte[] messageBytesRead = Utils.serializeMessage(toSerializeRead);
        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        Response res = _forum.read(_pubKey1, _pubKey1, 3, _signatureRead);

        messageBytesRead = Utils.serializeMessage(toSerializeRead2);
        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        _forum.read(_pubKey1, _pubKey1, 0, _signatureRead);

        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
    }

    @Test
    public void readGeneralRejectAttackTest() {
        List<Object> toSerializeRead = new ArrayList<>();
        toSerializeRead.add(_pubKey1);
        toSerializeRead.add(3);
        toSerializeRead.add(_nonce);

        List<Object> toSerializeRead2 = new ArrayList<>();
        toSerializeRead2.add(_pubKey1);
        toSerializeRead2.add(0);
        toSerializeRead2.add(_nonce + 1);

        byte[] messageBytesRead = Utils.serializeMessage(toSerializeRead);
        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        Response res = _forum.readGeneral(_pubKey1, 3, _signatureReadGeneral);

        messageBytesRead = Utils.serializeMessage(toSerializeRead2);
        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);

        _forum.readGeneral(_pubKey1, 0, _signatureReadGeneral);

        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
    }

    @AfterEach
    public void tearDown() {
        _forum = null;
        _message = null;
        _quotedAnnouncements = null;
        _timestamp = null;
        _signaturePost = null;
    }
}
