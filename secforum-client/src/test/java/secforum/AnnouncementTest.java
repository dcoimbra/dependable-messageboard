package secforum;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.Signing_RSA;
import security.Utils;

import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AnnouncementTest {

    private Announcement _announcement;
    private PublicKey _publicKey;
    private String _message;
    private List<Announcement> _quotedAnnouncements;
    private LocalDateTime _timestamp;
    private byte[] _signature;
    private int _counter;
    private NonceManager _manager;

    @BeforeEach
    public void setup() {
        try {
            _publicKey = Utils.loadPublicKey("1");
            _message = "";
            _quotedAnnouncements = new ArrayList<>();
            _timestamp = LocalDateTime.now();
            _counter = 0;
            _manager = new NonceManager();
            PrivateKey privateKey = Utils.loadPrivateKey("1");

            List<Object> toSerialize = new ArrayList<>();
            toSerialize.add(_publicKey);
            toSerialize.add(_message);
            toSerialize.add(_quotedAnnouncements);
            toSerialize.add(_timestamp);
            toSerialize.add(_manager.getClientNonce(_publicKey));
            byte[] messageBytes = Utils.serializeMessage(toSerialize);

            _signature = Signing_RSA.sign(messageBytes, privateKey);
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void validAnnouncement() {
        try {
            _announcement = new Announcement(_publicKey, _message, _quotedAnnouncements, _timestamp, _signature, _counter);
            assertEquals(Utils.loadPublicKey("1"), _announcement.getPubKey());
            assertEquals("", _announcement.getMessage());
            assertEquals(0, _announcement.nQuotedAnnouncements());

            List<Object> toSerialize = new ArrayList<>();
            toSerialize.add(_publicKey);
            toSerialize.add(_message);
            toSerialize.add(_quotedAnnouncements);
            toSerialize.add(_timestamp);
            toSerialize.add(_manager.getClientNonce(_publicKey));
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            assertTrue(Signing_RSA.verify(messageBytes, _signature, _publicKey));

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
            fail();
        }
    }

    @Test
    public void validAnnouncement254() {
        String repeated = new String(new char[254]);
        _announcement = new Announcement(_publicKey, repeated, _quotedAnnouncements, _timestamp, _signature, _counter);
        assertEquals(repeated, _announcement.getMessage());
    }

    @Test
    public void validAnnouncement255() {
        String repeated = new String(new char[255]);
        _announcement = new Announcement(_publicKey, repeated, _quotedAnnouncements, _timestamp, _signature, _counter);
        assertEquals(repeated, _announcement.getMessage());
    }

    @Test
    public void invalidAnnouncement() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement(_publicKey, new String(new char[256]), _quotedAnnouncements, _timestamp, _signature, _counter));
    }

    @Test
    public void invalidAnnouncementNullPubKey() {
        assertThrows(IllegalArgumentException.class,
                () -> _announcement = new Announcement(null, _message, _quotedAnnouncements, _timestamp, _signature, _counter));
    }

    @Test
    public void invalidAnnouncementNullMessage() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement(_publicKey, null, _quotedAnnouncements, _timestamp, _signature, _counter));
    }

    @Test
    public void invalidAnnouncementNullQuotedAnnouncements() {
        assertThrows(IllegalArgumentException.class,
                () -> new Announcement(_publicKey, _message, null, _timestamp, _signature, _counter));
    }

    @Test
    public void unsecureAnnouncement() {
        try {
            PublicKey pubKey = Utils.loadPublicKey("2");
            _announcement = new Announcement(pubKey, _message, _quotedAnnouncements, _timestamp, _signature, _counter);

            List<Object> toSerialize = new ArrayList<>();
            toSerialize.add(pubKey);
            toSerialize.add(_message);
            toSerialize.add(_quotedAnnouncements);
            toSerialize.add(_timestamp);
            toSerialize.add(_manager.getClientNonce(_publicKey));
            byte[] messageBytes = Utils.serializeMessage(toSerialize);
            assertFalse(Signing_RSA.verify(messageBytes, _signature, _publicKey));

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
            fail();
        }
    }
}
