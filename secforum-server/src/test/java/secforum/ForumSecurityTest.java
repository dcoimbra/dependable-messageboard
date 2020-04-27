//package secforum;
//
//import org.junit.jupiter.api.AfterEach;
//import org.junit.jupiter.api.BeforeAll;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import security.SigningSHA256_RSA;
//import security.Utils;
//
//import java.io.File;
//import java.io.IOException;
//import java.security.*;
//import java.util.ArrayList;
//import java.util.List;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//public class ForumSecurityTest {
//    private Forum _forum;
//    private static PublicKey _pubKey1;
//    private static PublicKey _pubKey2;
//    private String _message;
//    private List<String> _quotedAnnouncements;
//    private List<String> _wrongQuotedAnnouncements;
//    private byte[] _signaturePost;
//    private byte[] _signatureRead;
//    private static PrivateKey _privKey1;
//    private byte[] _signatureReadGeneral;
//    private static Integer _nonce;
//
//    @BeforeAll
//    public static void generate() {
//        try {
//            _nonce = 1;
//
//            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//
//            SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
//            SecureRandom random2 = SecureRandom.getInstance("SHA1PRNG");
//
//            generator.initialize(2048, random1);
//
//            KeyPair pair1 = generator.generateKeyPair();
//            _pubKey1 = pair1.getPublic();
//            _privKey1 = pair1.getPrivate();
//
//            generator.initialize(2048, random2);
//
//            KeyPair pair2 = generator.generateKeyPair();
//            _pubKey2 = pair2.getPublic();
//        } catch (NoSuchAlgorithmException e) {
//            fail();
//        }
//    }
//
//    @BeforeEach
//    public void setUp() {
//        try {
//            _forum = new Forum("server");
//
//            _forum.register(_pubKey1);
//
//            _message = "ola";
//            _quotedAnnouncements = new ArrayList<>();
//            _wrongQuotedAnnouncements = new ArrayList<>();
//            _wrongQuotedAnnouncements.add("a");
//        } catch (IOException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void getNonceSignatureTest() {
//        Response res = _forum.getNonce(_pubKey1);
//
//        try{
//            Integer nonce = res.verifyNonce(_forum.loadPublicKey());
//            assertEquals(1, nonce);
//        } catch (IllegalArgumentException iae) {
//            System.out.println(iae.getMessage());
//            fail();
//        }
//    }
//
//    @Test
//    public void getNonceNotRegistered() {
//         Response res = _forum.getNonce(_pubKey2);
//         assertEquals("Your public key is not registered.", res.getException().getMessage());
//    }
//
//    @Test
//    public void postReplayAttackTest() {
//        try {
//            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce);
//            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//
//            _forum.post(_pubKey1, _message, new ArrayList<>(), _signaturePost);
//            Response res = _forum.post(_pubKey1, _message, new ArrayList<>(), _signaturePost);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void postGeneralReplayAttackTest() {
//        try {
//            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce);
//            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//
//            _forum.postGeneral(_pubKey1, _message, new ArrayList<>(), _signaturePost);
//            Response res = _forum.postGeneral(_pubKey1, _message, new ArrayList<>(), _signaturePost);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//
//
//    @Test
//    public void readReplayAttack() {
//        try {
//            byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 0, _nonce);
//            _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//            _forum.read(_pubKey1, _pubKey1, 0, _signatureRead);
//            Response res = _forum.read(_pubKey1, _pubKey1, 0, _signatureRead);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void readGeneralReplayAttack() {
//        try {
//            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, 0, _nonce);
//            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);
//            _forum.readGeneral(_pubKey1, 0, _signatureReadGeneral);
//            Response res = _forum.readGeneral(_pubKey1, 0, _signatureReadGeneral);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void postIntegrityTest() {
//        try {
//            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce);
//            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//            Response res = _forum.post(_pubKey1, "attack", new ArrayList<>(), _signaturePost);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void postGeneralIntegrityTest() {
//        try {
//            byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce);
//            _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//            Response res = _forum.postGeneral(_pubKey1, "attack", new ArrayList<>(), _signaturePost);
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
//            Response res = _forum.read(_pubKey1, _pubKey1, 404, _signatureRead);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void readGeneralIntegrityTest() {
//        try {
//            byte[] messageBytesReadGeneral = Utils.serializeMessage(_pubKey1, 0, _nonce);
//            _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesReadGeneral, _privKey1);
//            Response res = _forum.readGeneral(_pubKey1, 404, _signatureReadGeneral);
//
//            assertEquals("Security error. Message was altered.", res.getException().getMessage());
//        } catch (IllegalArgumentException e) {
//            fail();
//        }
//    }
//
//    @Test
//    public void postRejectAttackTest() {
//        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce);
//        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//
//        Response res = _forum.post(_pubKey1, _message, _wrongQuotedAnnouncements, _signaturePost);
//
//        messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 1);
//        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//
//        _forum.post(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//
//        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
//    }
//
//    @Test
//    public void postGeneralRejectAttackTest() {
//        byte[] messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _wrongQuotedAnnouncements, _nonce);
//        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//
//        Response res = _forum.postGeneral(_pubKey1, _message, _wrongQuotedAnnouncements, _signaturePost);
//
//        messageBytesPost = Utils.serializeMessage(_pubKey1, _message, _quotedAnnouncements, _nonce + 1);
//        _signaturePost = SigningSHA256_RSA.sign(messageBytesPost, _privKey1);
//
//        _forum.postGeneral(_pubKey1, _message, _quotedAnnouncements, _signaturePost);
//
//        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
//    }
//
//    @Test
//    public void readRejectAttackTest() {
//        byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 3, _nonce);
//        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        Response res = _forum.read(_pubKey1, _pubKey1, 3, _signatureRead);
//
//        messageBytesRead = Utils.serializeMessage(_pubKey1, _pubKey1, 0, _nonce + 1);
//        _signatureRead = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        _forum.read(_pubKey1, _pubKey1, 0, _signatureRead);
//
//        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
//    }
//
//    @Test
//    public void readGeneralRejectAttackTest() {
//        byte[] messageBytesRead = Utils.serializeMessage(_pubKey1, 3, _nonce);
//        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        Response res = _forum.readGeneral(_pubKey1, 3, _signatureReadGeneral);
//
//        messageBytesRead = Utils.serializeMessage(_pubKey1, 0, _nonce + 1);
//        _signatureReadGeneral = SigningSHA256_RSA.sign(messageBytesRead, _privKey1);
//
//        _forum.readGeneral(_pubKey1, 0, _signatureReadGeneral);
//
//        assertThrows(IllegalArgumentException.class, () -> res.verify(_pubKey1, _nonce + 1));
//    }
//
//    @AfterEach
//    public void tearDown() {
//        _forum = null;
//        _message = null;
//        _quotedAnnouncements = null;
//        _signaturePost = null;
//
//        File forum = new File("src/main/resources/forum.ser");
//        File backup = new File("src/main/resources/forum_backup.ser");
//        forum.delete();
//        backup.delete();
//    }
//}