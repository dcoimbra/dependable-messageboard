/*
  @author GROUP 25
 * Class for announcements to be posted in forum boards
 */

package secforum;

import security.HashingSHA256;
import security.SigningSHA256_RSA;
import security.Utils;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Announcement implements Serializable {
    private final String _id;
    private final PublicKey _pubKey;
    private final String _message;
    private final List<Announcement> _quotedAnnouncements;
    private final LocalDateTime _timestamp;
    private final Integer _nonce;
    private final int _wts;
    private final int _rank;
    private final byte[] _signature;

    /**
     *
     * @param pubKey The author of the message
     * @param message The message to be posted
     * @param quotedAnnouncements List of announcements that were referred to
     * @param signature Signature of the author
     * @throws RemoteException if a message is longer than 255 characters ot if any of the arguments are null
     */
    public Announcement(PublicKey pubKey, String message, List<Announcement> quotedAnnouncements, Integer nonce, byte[] signature, int counter, int wts, int rank) throws RemoteException {
        if (message == null || pubKey == null || quotedAnnouncements == null) {
            throw new RemoteException("Arguments cannot be null");
        }

        if (message.length() > 255) {
            throw new RemoteException("Message cannot have more than 255 characters");
        }

        _id = HashingSHA256.getDigest(pubKey.toString() + counter);
        _pubKey = pubKey;
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;
        _timestamp = LocalDateTime.now();
        _nonce = nonce;
        _wts = wts;
        _rank = rank;
        _signature = signature;
    }

    public boolean verify() {
        List<String> quotedIds = new ArrayList<>();

        for (Announcement announcement : _quotedAnnouncements) {
            quotedIds.add(announcement.getId());
        }

        byte[] messageBytes = Utils.serializeMessage(_pubKey, _message, quotedIds, _nonce, _wts, _rank);

        return (SigningSHA256_RSA.verify(messageBytes, _signature, _pubKey));
    }

    public String getId() {
        return _id;
    }

    public String getMessage() {
        return _message;
    }

    public PublicKey getPubKey() {
        return _pubKey;
    }

    public int nQuotedAnnouncements() {
        return _quotedAnnouncements.size();
    }

    public Integer getNonce() {
        return _nonce;
    }

    public int getTs() { return _wts; }

    public int getRank() {return _rank; }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append("ID: ").append(_id);
        builder.append("\nAuthor's pubKey:\n").append(_pubKey);
        builder.append("\nPublished time: ").append(_timestamp);
        builder.append("\nQuoted Announcements: ");

        if(_quotedAnnouncements.size() > 0) {
            for(Announcement a : _quotedAnnouncements) {
                builder.append(a._id).append("; ");
            }
        }
        else {
            builder.append("none");
        }

        builder.append("\nMessage: ").append(_message).append("\n");

        return builder.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Announcement that = (Announcement) o;
        return _wts == that._wts &&
                Objects.equals(_id, that._id) &&
                Objects.equals(_pubKey, that._pubKey) &&
                Objects.equals(_message, that._message) &&
                Objects.equals(_quotedAnnouncements, that._quotedAnnouncements);
    }
}