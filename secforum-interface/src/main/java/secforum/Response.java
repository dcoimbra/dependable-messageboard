package secforum;

import security.SigningSHA256_RSA;
import security.Utils;

import java.io.IOException;
import java.io.Serializable;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public class Response implements Serializable {
    private List<Announcement> _announcements;
    private String _response;
    private byte[] _signature;

    public Response(List<Announcement> announcements, String response, PrivateKey privKey, Integer nonce) {
        _announcements = announcements;
        _response = response;

        List<Object> toSerialize = new ArrayList<>();
        byte[] messageBytes;

        if(response == null) {
            toSerialize.add(announcements);
            toSerialize.add(nonce);
        }
        else if(announcements == null) {
            toSerialize.add(response);
            toSerialize.add(nonce);
        }
        try {
            messageBytes = Utils.serializeMessage(toSerialize);
            _signature = SigningSHA256_RSA.sign(messageBytes, privKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public List<Announcement> getAnnouncements() {
        return _announcements;
    }

    public String getResponse() {
        return _response;
    }

    public byte[] getSignature() {
        return _signature;
    }
}
