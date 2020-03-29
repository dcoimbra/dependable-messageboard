package secforum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.Signing_RSA;
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
    private PublicKey _pubKey1;
    private PublicKey _pubKey2;
    private String _message;
    private List<String> _quotedAnnouncements;
    private LocalDateTime _timestamp;
    private byte[] _signature;
    private PrivateKey _privKey1;
    private PrivateKey _privKey2;

    @BeforeEach
    public void setUp() {
        try {
            _forum = new Forum();

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
            _signature = Signing_RSA.sign(messageBytes, _privKey1);

        } catch (NoSuchAlgorithmException | IOException e) {
            fail();
        }
    }

    @Test
    public void registerValidTest() {
        try {
            Response res = _forum.register(_pubKey1);
            assertNull(res.getAnnouncements());
            assertEquals("Registered successfully", res.getResponse());
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void registerAlreadyRegistered() {
        try {
            _forum.register(_pubKey1);
        } catch (RemoteException e) {
            fail();
        }

        assertThrows(RemoteException.class, () -> _forum.register(_pubKey1));
    }

    public void postValidTest() {
        try {
            _forum.register(_pubKey1);
        } catch (RemoteException e) {
            fail();
        }
    }
}
