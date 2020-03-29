package secforum;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

public class ForumTest {
    private Forum _forum;
    private static PublicKey _pubKey1;
    private static PublicKey _pubKey2;
    private String _message;
    private List<String> _quotedAnnouncements;
    private LocalDateTime _timestamp;
    private byte[] _signature;
    private static PrivateKey _privKey1;
    private static PrivateKey _privKey2;

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

            _message = "";
            _quotedAnnouncements = new ArrayList<>();
            _timestamp = LocalDateTime.now();

            List<Object> toSerialize = new ArrayList<>();
            toSerialize.add(_pubKey1);
            toSerialize.add(_message);
            toSerialize.add(_quotedAnnouncements);
            toSerialize.add(_timestamp);
            toSerialize.add(_forum.getAccounts().get(_pubKey1).getNonce());

            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            _signature = SigningSHA256_RSA.sign(messageBytes, _privKey1);

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
            Response res = _forum.post(_pubKey1, _message, _quotedAnnouncements, _timestamp, _signature);
            assertNull(res.getAnnouncements());
            assertEquals("Successfully uploaded the post", res.getResponse());

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
        _signature = null;
    }
}
