package secforum;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;


public class Account implements Serializable {

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

    public Account(PublicKey pubKey) {
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
    }

    protected Map<ClientCallbackInterface, int[]> getListeners() {
        return _listeners;
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

            System.out.println("Waiting for echo quorum...");
            _echoLatch.await(10, TimeUnit.SECONDS);

            EchoMessage echoMessage = Forum.compareMessages(_echos);

            if (echoMessage == null) {
                System.out.println("No echo quorum.");
                throw new RemoteException("No echo quorum");
            }

            System.out.println("Echo quorum. Ready.");

            threads = new ArrayList<>();

            for (int i = 0; i < 3; i++) {
                threads.add(new Thread(new ReadyRequest(echoMessage, otherServers.get(i))));
                threads.get(i).start();
            }

            for (Thread t : threads) {
                t.join();
            }

            System.out.println("Waiting for ready quorum...");
            _readyLatch.await(10, TimeUnit.SECONDS);

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
        if (message.verify(publicKey, message.serialize())) {
            System.out.println("(echo) Verified.");
            addEcho(message, _echos, _echoLatch);
        } else {
            System.out.println("(echo) Not verified");
        }
    }

    static void addEcho(EchoMessage message, List<EchoMessage> echos, CountDownLatch echoLatch) {
        echos.add(message);
        echoLatch.countDown();
    }

    public void ready(EchoMessage message, PublicKey publicKey) {
        if (message.verify(publicKey, message.serialize())) {
            System.out.println("(ready) Verified.");
            addReady(message, _readys, _readyLatch);
        } else {
            System.out.println("(ready) Not verified");
        }
    }

    static void addReady(EchoMessage message, List<EchoMessage> readys, CountDownLatch readyLatch) {
        readys.add(message);
        readyLatch.countDown();
    }
}
