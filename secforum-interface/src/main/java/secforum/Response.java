package secforum;

import security.Signing_RSA;

import java.io.Serializable;
import java.security.PrivateKey;
import java.util.List;

public class Response implements Serializable {
    private List<Announcement> _announcements;
    private String _response;
    private String _signature;

    public Response(List<Announcement> announcements, String response, PrivateKey privKey) {
        _announcements = announcements;
        _response = response;

        if(response == null) {
            _signature = Signing_RSA.sign(announcements.toString(), privKey);
        }
        else if(announcements == null) {
            _signature = Signing_RSA.sign(response, privKey);
        }
    }

    public List<Announcement> getAnnouncements() {
        return _announcements;
    }

    public String getResponse() {
        return _response;
    }

    public String getSignature() {
        return _signature;
    }
}
