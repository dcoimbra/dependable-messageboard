/*
  @author GROUP 25
 * Class for announcements to be posted in forum boards
 */

package secforum;

import security.HashingSHA256;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

public class Announcement implements Serializable {
    private String _id;
    private PublicKey _pubKey;
    private String _message;
    private List<Announcement> _quotedAnnouncements;
    private LocalDateTime _timestamp;
    private Integer _nonce;
    private byte[] _signature;

    /**
     *
     * @param pubKey The author of the message
     * @param message The message to be posted
     * @param quotedAnnouncements List of announcements that were referred to
     * @param signature Signature of the author
     * @throws RemoteException if a message is longer than 255 characters ot if any of the arguments are null
     */
    public Announcement(PublicKey pubKey, String message, List<Announcement> quotedAnnouncements, Integer nonce, byte[] signature, int counter) throws RemoteException {
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
        _signature = signature;
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
}