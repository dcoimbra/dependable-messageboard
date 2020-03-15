/**
 * @author GROUP 25
 * Class for announcements to be posted in forum boards
 */

package secforum;

import java.time.LocalDateTime;

public class Announcement {
    private String _message;
    private String _username;
    private LocalDateTime _timestamp;

    /**
     *
     * @param message The message to be posted
     * @param username The author of the message
     * @throws IllegalArgumentException if a message is longer than 255 characters
     */
    public Announcement(String message, String username) throws IllegalArgumentException {

        if (message.length() > 255) {
            throw new IllegalArgumentException("Message cannot have more than 255 characters");
        }

        _message = message;
        _username = username;

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
 