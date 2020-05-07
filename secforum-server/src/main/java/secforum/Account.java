package secforum;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;


public class Account implements Serializable {

    private final int _id;
    private final PublicKey _pubKey;
    private final Board _announcementsBoard;
    private int _counter;
    private Integer _nonce;
    private int _ts;
    private final Map<ClientCallbackInterface, int[]> _listeners;
    private transient CountDownLatch _echoLatch;
    private final List<EchoMessage> _echos;
    private transient CountDownLatch _readyLatch;
    private final List<EchoMessage> _readys;
    private final int[] _broadcastNonces;
    private final PrivateKey _privKey;

    public Account(PublicKey pubKey, int id, PrivateKey privKey) {
        _id = id;
        _pubKey = pubKey;
        _announcementsBoard = new Board();
        _counter = 0;
        _nonce = 0;
        _ts = 0;
        _listeners = new HashMap<>();
        _echoLatch = new CountDownLatch(3);
        _readyLatch = new CountDownLatch(3);
        _echos = new Vector<>();
        _readys = new Vector<>();
        _broadcastNonces = new int[]{0, 0, 0, 0};
        _privKey = privKey;
    }

    protected Map<ClientCallbackInterface, int[]> getListeners() {
        return _listeners;
    }

    public int getServerBroadcastNonce(int i) {
        return _broadcastNonces[i];
    }

    public void setServerBroadcastNonce(int i, int nonce) {
        _broadcastNonces[i] = nonce;
    }

    public void incMyBroadcastNonce() {
        _broadcastNonces[_id]++;
    }

    public int getMyBroadcastNonce() {
        return _broadcastNonces[_id];
    }

    public void setTs(int wts) {
        _ts = wts;
    }

    public int getTs() {
        return _ts;
    }

    public int getCounter() {
        return _counter++;
    }

    public Integer getNonce() {
        return _nonce;
    }

    public void setNonce() {
        _nonce = _nonce + 1;
    }

    public List<Announcement> getBoardAnnouncements() {
        return _announcementsBoard.getAnnouncements();
    }

    public synchronized void post(String message, List<Announcement> a, byte[] signature, int wts, int rank) throws RemoteException {
        if (wts == _ts + 1) {
            setTs(wts);
            _announcementsBoard.post(_pubKey, message, a, _nonce, signature, _counter, wts, rank);
            _counter++;
        } else {
            throw new RemoteException("\nRegister error! Request already processed!");
        }
    }

    public List<Announcement> read(int number, int rid, ClientCallbackInterface listener) throws RemoteException {
        _listeners.put(listener, new int[]{number, rid});
        return _announcementsBoard.read(number);
    }

    protected List<Announcement> read(int number) throws RemoteException {
        return _announcementsBoard.read(number);
    }

    protected void removeListener(ClientCallbackInterface listener) {
        _listeners.remove(listener);
    }

    public EchoMessage byzantineReliableBroadcast(EchoMessage message, List<ForumReliableBroadcastInterface> otherServers) {
        try {
            List<Thread> threads = new ArrayList<>();

            System.out.println("Echo.");
            for (int i = 0; i < 3; i++) {
                threads.add(new Thread(new EchoRequest(message, otherServers.get(i))));
                threads.get(i).start();
            }

            for (Thread t : threads) {
                t.join();
            }

            incMyBroadcastNonce();

            System.out.println("Waiting for echo quorum...");
            _echoLatch.await(5, TimeUnit.SECONDS);

            _echos.add(message);
            EchoMessage echoMessage = Forum.compareMessages(_echos);

            if (echoMessage == null) {
                System.out.println("No echo quorum.");
                throw new RemoteException("No echo quorum");
            }

            System.out.println("Echo quorum. Ready.");

            echoMessage.setServerId(_id);
            echoMessage.setNonce(getMyBroadcastNonce());
            echoMessage.sign(_privKey);

            threads = new ArrayList<>();

            for (int i = 0; i < 3; i++) {
                threads.add(new Thread(new ReadyRequest(echoMessage, otherServers.get(i))));
                threads.get(i).start();
            }

            for (Thread t : threads) {
                t.join();
            }

            incMyBroadcastNonce();

            System.out.println("Waiting for ready quorum...");
            _readyLatch.await(5, TimeUnit.SECONDS);

            _readys.add(echoMessage);
            EchoMessage readyMessage = Forum.compareMessages(_readys);

            if (readyMessage == null) {
                System.out.println("No ready quorum.");
                throw new RemoteException("No ready quorum.");
            }

            System.out.println("Ready quorum. Delivering message.");
            _echos.clear();
            _echoLatch = new CountDownLatch(3);
            _readys.clear();
            _readyLatch = new CountDownLatch(3);
            return readyMessage;
        } catch (RemoteException | InterruptedException e) {
            return null;
        }
    }

    public void echo(EchoMessage message, PublicKey publicKey) {
        int id = message.getServerId();
        int serverNonce = getServerBroadcastNonce(id);

        if (message.verify(publicKey, message.serialize()) && (message.getNonce() > serverNonce)) {
            System.out.println("(echo) Verified.");
            addEcho(message, _echos, _echoLatch);
            setServerBroadcastNonce(id, message.getNonce());
        } else {
            System.out.println("(echo) Not verified");
        }
    }

    static void addEcho(EchoMessage message, List<EchoMessage> echos, CountDownLatch echoLatch) {
        echos.add(message);
        echoLatch.countDown();
    }

    public void ready(EchoMessage message, PublicKey publicKey) {

        int id = message.getServerId();
        int serverNonce = getServerBroadcastNonce(id);

        if (message.verify(publicKey, message.serialize()) && (message.getNonce() > serverNonce)) {
            System.out.println("(ready) Verified.");
            addReady(message, _readys, _readyLatch);
            setServerBroadcastNonce(id, message.getNonce());
        } else {
            System.out.println("(ready) Not verified");
        }
    }

    static void addReady(EchoMessage message, List<EchoMessage> readys, CountDownLatch readyLatch) {
        readys.add(message);
        readyLatch.countDown();
    }
}
