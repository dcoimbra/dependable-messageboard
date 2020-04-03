package secforum;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class Board implements Serializable {
    private List<Announcement> _announcements;

    public Board() {
        _announcements = new ArrayList<>();
    }

    public void post(PublicKey pubKey, String message, List<Announcement> a, Integer nonce, byte[] signature, int counter) throws RemoteException {

        Announcement announcement = new Announcement(pubKey, message, a, nonce, signature, counter);
        _announcements.add(0, announcement);
    }

    public List<Announcement> read(int number) throws RemoteException {

        if (number > _announcements.size()) {
            throw new RemoteException("Board does not have that many announcements");
        }

        if (number == 0) {
            return new ArrayList<>(_announcements);
        }

        List<Announcement> result = new ArrayList<>();

        for (int j = 0; j < number; j++) {
            result.add(_announcements.get(j));
        }

        return result;
    }

    public List<Announcement> getAnnouncements() {
        return new ArrayList<>(_announcements);
    }
}
