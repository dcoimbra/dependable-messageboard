/*
  @author GROUP 25
 * Class for announcements to be posted in forum boards
 */

package secforum;

import java.time.LocalDateTime;
import java.util.List;

public class Announcement {
    private String _message;
    private String _username;
    private List _quotedAnnouncements;
    private LocalDateTime _timestamp;

    /**
     *
     * @param message The message to be posted
     * @param username The author of the message
     * @throws IllegalArgumentException if a message is longer than 255 characters ot if any of the arguments are null
     */
    public Announcement(String message, String username, List<Announcement> quotedAnnouncements) throws IllegalArgumentException {
        if (message == null || username == null || quotedAnnouncements == null) {
            throw new IllegalArgumentException("Arguments cannot be null");
        }

        if (message.length() > 255) {
            throw new IllegalArgumentException("Message cannot have more than 255 characters");
        }

        _message = message;
        _username = username;
        _quotedAnnouncements = quotedAnnouncements;

        _timestamp = LocalDateTime.now();
    }

    public String getMessage() {
        return _message;
    }

    public String getUsername() {
        return _username;
    }

    public LocalDateTime getTimestamp() {
        return _timestamp;
    }
}
 