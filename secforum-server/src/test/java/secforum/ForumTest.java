package secforum;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ForumTest {
    private Forum _forum;
    private static PublicKey _pubKey1;
    private static PublicKey _pubKey2;
    private String _message;
    private List<String> _quotedAnnouncements;
    private LocalDateTime _timestamp;
    private byte[] _signaturePost;
    private byte[] _signatureRead;
    private static PrivateKey _privKey1;
    private static PrivateKey _privKey2;
    private byte[] _signatureReadGeneral;

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
            _forum = new Forum();

            _forum.register(_pubKey1);

            _message = "ola";
            _quotedAnnouncements = new ArrayList<>();
            _timestamp = LocalDateTime.now();

            List<Object> toSerializePost = new ArrayList<>();
            toSerializePost.add(_pubKey1);
            toSerializePost.add(_message);
            toSerializePost.add(_quotedAnnouncements);
            toSerializePost.add(_timestamp);
            toSerializePost.add(_forum.getAccounts().get(_pubKey1).getNonce());

            byte[] messageBytesPost = Utils.serializeMessage(toSerializePost);
            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);

            List<Object> toSerializeRead = new ArrayList<>();
            toSerializeRead.add(_pubKey2);
            toSerializeRead.add(_pubKey1);
            toSerializeRead.add(1);
            toSerializeRead.add(1);

            byte[] messageBytesRead = Utils.serializeMessage(toSerializeRead);
            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey2);

            List<Object> toSerializeReadGeneral = new ArrayList<>();
            toSerializeReadGeneral.add(_pubKey2);
            toSerializeReadGeneral.add(1);
            toSerializeReadGeneral.add(1);

            byte[] messageBytesReadGeneral = Utils.serializeMessage(toSerializeReadGeneral);
            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey2);

        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void registerValidTest() {
        try {
            Response res = _forum.register(_pubKey2);
            assertNull(res.getAnnouncements());
            assertEquals("Registered successfully", res.getResponse());
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void registerAlreadyRegistered() {
        assertThrows(RemoteException.class, () -> _forum.register(_pubKey1));
    }

    @Test
    public void postValidTest() {
        try {
            Response res = _forum.post(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            assertNull(res.getAnnouncements());
            assertEquals("Successfully uploaded the post", res.getResponse());

        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidPostNotRegistered() {
       assertThrows(RemoteException.class, () -> _forum.post(_pubKey2, _message, _quotedAnnouncements, _timestamp, _signaturePost));
    }

    @Test
    public void invalidPostAnnouncementDoesNotExist() {
        List<String> wrongQuotedAnnouncements = new ArrayList<>();
        wrongQuotedAnnouncements.add("a");
        assertThrows(RemoteException.class, () -> _forum.post(_pubKey1, _message, wrongQuotedAnnouncements, _timestamp, _signaturePost));
    }

    @Test
    public void postGeneralValidTest() {
        try {
            Response res = _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            assertNull(res.getAnnouncements());
            assertEquals("Successfully uploaded the post", res.getResponse());

        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidPostGeneralNotRegistered() {
        assertThrows(RemoteException.class, () -> _forum.postGeneral(_pubKey2, _message, _quotedAnnouncements, _timestamp, _signaturePost));
    }

    @Test
    public void invalidPostGeneralAnnouncementDoesNotExist() {
        List<String> wrongQuotedAnnouncements = new ArrayList<>();
        wrongQuotedAnnouncements.add("a");
        assertThrows(RemoteException.class, () -> _forum.postGeneral(_pubKey1, _message, wrongQuotedAnnouncements, _timestamp, _signaturePost));
    }

    @Test
    public void validRead() {
        try {
            _forum.register(_pubKey2);
            _forum.post(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            Response res = _forum.read(_pubKey2, _pubKey1, 1, _signatureRead);

            assertNull(res.getResponse());

            Announcement a = new Announcement(_pubKey1, _message, new ArrayList<>(), _timestamp, _signaturePost, 0);
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
        try {
            _forum.register(_pubKey2);
            _forum.post(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            assertThrows(RemoteException.class, () -> _forum.read(_pubKey2, _pubKey1, -1, _signatureRead));
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidReadTooHigh() {
        try {
            _forum.register(_pubKey2);
            _forum.post(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            assertThrows(RemoteException.class, () -> _forum.read(_pubKey2, _pubKey1, 2, _signatureRead));
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void validReadGeneral() {
        try {
            _forum.register(_pubKey2);
            _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            Response res = _forum.readGeneral(_pubKey2, 1, _signatureReadGeneral);

            assertNull(res.getResponse());

            Announcement a = new Announcement(_pubKey1, _message, new ArrayList<>(), _timestamp, _signaturePost, 0);
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
        try {
            _forum.register(_pubKey2);
            _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            assertThrows(RemoteException.class, () -> _forum.readGeneral(_pubKey2, -1, _signatureRead));
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidReadGeneralTooHigh() {
        try {
            _forum.register(_pubKey2);
            _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signaturePost);
            assertThrows(RemoteException.class, () -> _forum.readGeneral(_pubKey2, 2, _signatureRead));
        } catch (RemoteException e) {
            fail();
        }
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
