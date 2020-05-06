package secforum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AnnouncementTests {

    private Announcement _announcement;
    private PublicKey _publicKey;
    private String _message;
    private List<Announcement> _quotedAnnouncements;
    private byte[] _signature;
    private int _counter;
    private int _nonce;
    private int _wts;
    private int _rank;

    @BeforeEach
    public void setup() {
        try {
            _publicKey = Utils.loadPublicKey("1");
            _message = "Hello World!";
            _quotedAnnouncements = new ArrayList<>();
            _counter = 0;
            _nonce = 0;
            _wts = 0;
            _rank = 1;
            PrivateKey privateKey = Utils.loadPrivateKey("1", "client1");

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, _nonce);

            _signature = SigningSHA256_RSA.sign(messageBytes, privateKey);
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void validAnnouncement() {
        try {
            _announcement = new Announcement(_publicKey, _message, _quotedAnnouncements, _nonce, _signature, _counter, _wts, _rank);
            assertEquals(Utils.loadPublicKey("1"), _announcement.getPubKey());
            assertEquals("", _announcement.getMessage());
            assertEquals(0, _announcement.nQuotedAnnouncements());

            byte[] messageBytes = Utils.serializeMessage(_publicKey, _message, _quotedAnnouncements, _nonce);
            assertTrue(SigningSHA256_RSA.verify(messageBytes, _signature, _publicKey));

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
            fail();
        }
    }

    @Test
    public void validAnnouncement254() {
        String repeated = new String(new char[254]);
        try {
            _announcement = new Announcement(_publicKey, repeated, _quotedAnnouncements, _nonce, _signature, _counter, _wts, _rank);
            assertEquals(repeated, _announcement.getMessage());
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void validAnnouncement255() {
        String repeated = new String(new char[255]);
        try {
            _announcement = new Announcement(_publicKey, repeated, _quotedAnnouncements, _nonce, _signature, _counter, _wts, _rank);
            assertEquals(repeated, _announcement.getMessage());
        } catch (RemoteException e) {
            fail();
        }
    }

    @Test
    public void invalidAnnouncement() {
        assertThrows(RemoteException.class,
                () -> new Announcement(_publicKey, new String(new char[256]), _quotedAnnouncements, _nonce, _signature, _counter, _wts, _rank));
    }

    @Test
    public void invalidAnnouncementNullPubKey() {
        assertThrows(RemoteException.class,
                () -> _announcement = new Announcement(null, _message, _quotedAnnouncements, _nonce, _signature, _counter, _wts, _rank));
    }

    @Test
    public void invalidAnnouncementNullMessage() {
        assertThrows(RemoteException.class,
                () -> new Announcement(_publicKey, null, _quotedAnnouncements, _nonce, _signature, _counter, _wts, _rank));
    }

    @Test
    public void invalidAnnouncementNullQuotedAnnouncements() {
        assertThrows(RemoteException.class,
                () -> new Announcement(_publicKey, _message, null, _nonce, _signature, _counter, _wts, _rank));
    }
}
