/*
  @author GROUP 25
 * Class for announcements to be posted in forum boards
 */

package secforum;

import java.io.Serializable;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

public class Announcement implements Serializable {
    private PublicKey _pubKey;
    private String _message;
    private List _quotedAnnouncements;
    private LocalDateTime _timestamp;

    /**
     *
     * @param pubKey The author of the message
     * @param message The message to be posted
     * @param quotedAnnouncements List of announcements that were referred to
     * @throws IllegalArgumentException if a message is longer than 255 characters ot if any of the arguments are null
     */
    public Announcement(PublicKey pubKey, String message, List<Announcement> quotedAnnouncements) throws IllegalArgumentException {
        if (message == null || pubKey == null || quotedAnnouncements == null) {
            throw new IllegalArgumentException("Arguments cannot be null");
        }

        if (message.length() > 255) {
            throw new IllegalArgumentException("Message cannot have more than 255 characters");
        }

        _pubKey = pubKey;
        _message = message;
        _quotedAnnouncements = quotedAnnouncements;

        _timestamp = LocalDateTime.now();
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

    public LocalDateTime getTimestamp() {
        return _timestamp;
    }
}
 