package secforum;

import secforum.response.Response;
import security.Utils;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client implements ClientCallbackInterface {
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private PublicKey _serverKey;
    private final List<ForumInterface> _forums = new ArrayList<>();
    private Scanner _keyboardSc;
    private Remote _clientStub;
    private static final int _f = 1;
    private static final int _N = 3 * _f + 1;
    private ByzantineAtomicRegister _atomicRegister;
    private ByzantineRegularRegister _regularRegisterGeneral;
    private static int _rank;
    private boolean _firstTime;

    private static final String BYZANTINE_ERROR = "\nERROR: Byzantine fault detected.";
    private static final String WRITE_RESPONSE = "Post verified!";

    public Client(String id) {
        try {
            _clientStub = UnicastRemoteObject.exportObject(this, 8887 + Integer.parseInt(id));
            _keyboardSc = new Scanner(System.in);
            _firstTime = true;

            _publicKey = Utils.loadPublicKey(id);
            _serverKey = Utils.loadPublicKeyFromCerificate("src/main/resources/server.cer");
            _rank = Integer.parseInt(id);

            System.out.println("Enter your private key password:");
            String password = _keyboardSc.nextLine();
            _privateKey = Utils.loadPrivateKey(id, password);
            _atomicRegister = new ByzantineAtomicRegister();
            _regularRegisterGeneral = new ByzantineRegularRegister();

            String name;
            for (int i = 0; i < _N; i++) {
                name = "//localhost:" + (1099 + i) + "/forum" + i;
                _forums.add((ForumInterface) Naming.lookup(name));
                System.out.println("Found server: " + name);
            }

        } catch (NotBoundException | NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException |
                UnrecoverableKeyException e) {
            System.out.println(e.getMessage());
        }
    }

    public void start() {
        int command, nAnnouncement;
        String id, message;
        PublicKey publicKey;

        while (true) {
            System.out.println("\n1 - register\n2 - post\n3 - read\n4 - postGeneral\n5 - readGeneral\n6 - exit");

            try {
                command = Integer.parseInt(_keyboardSc.nextLine());
                List<Thread> threads = new ArrayList<>();
                List<String> quotedAnnouncements;
                String response;

                switch (command) {
                    case 1: // register
                        register(threads);
                        break;

                    case 2: // post
                        System.out.println("\nEnter the message to be posted:");
                        message = _keyboardSc.nextLine();

                        quotedAnnouncements = new ArrayList<>();
                        nAnnouncement = requestInt("\nEnter the number of announcements to be quoted:");

                        for (int i = 0; i < nAnnouncement; i++) {
                            System.out.println("\n(" + i + 1 + ") Enter the announcement ID:");
                            quotedAnnouncements.add(_keyboardSc.nextLine());
                        }

                        response = post(threads, message, quotedAnnouncements);
                        System.out.println(response);
                        break;

                    case 3: // read
                        System.out.println("\nEnter the id of the client you want to read from:");
                        id = _keyboardSc.nextLine();

                        publicKey = Utils.loadPublicKey(id);
                        nAnnouncement = requestInt("\nEnter the number of announcements to read:");

                        response = read(threads, publicKey, nAnnouncement);
                        System.out.println(response);
                        break;

                    case 4: // postGeneral
                        System.out.println("\nEnter the message to be posted:");
                        message = _keyboardSc.nextLine();

                        quotedAnnouncements = new ArrayList<>();
                        nAnnouncement = requestInt("\nEnter the number of announcements to be quoted:");

                        for (int i = 0; i < nAnnouncement; i++) {
                            System.out.println("\n(" + i + 1 + ") Enter the announcement ID:");
                            quotedAnnouncements.add(_keyboardSc.nextLine());
                        }

                        response = postGeneral(threads, message, quotedAnnouncements);
                        System.out.println(response);
                        break;

                    case 5: // readGeneral
                        nAnnouncement = requestInt("\nEnter the number of announcements to read:");

                        response = readGeneral(threads, nAnnouncement);
                        System.out.println(response);
                        break;

                    case 6: // exit
                        System.out.println("Thank you for using the app");
                        return;

                    default:
                        System.out.println("ERROR! Command must be between 1 and 6!");
                        break;
                }
            } catch (NumberFormatException e) {
                System.out.println("ERROR! Command must be a number between 1 and 6!");
            } catch (InterruptedException e) {
                System.out.println("Thread interrupted.");
            } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
                System.out.println("Internal error.");
            }
        }
    }

    public void register(List<Thread> threads) throws InterruptedException {
        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new RegisterRequest(_forums.get(i), _publicKey, _serverKey)));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }
    }

    public String post(List<Thread> threads, String message, List<String> quotedAnnouncements) throws InterruptedException {
        _atomicRegister.clearAcklist();

        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new PostRequest(_forums.get(i), _privateKey, _publicKey, _serverKey,
                    message, quotedAnnouncements, _rank, _atomicRegister, _firstTime)));
            threads.get(i).start();
        }

        if (_firstTime) {
            _firstTime = false;
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }

        System.out.println("\nVerifying post....");
        if (_atomicRegister.getAcklist().size() > (_N + _f) / 2) {
            _atomicRegister.incWts();
            return WRITE_RESPONSE;
        } else {
            throw new IllegalArgumentException(BYZANTINE_ERROR);
        }
    }

    public String read(List<Thread> threads, PublicKey publicKey, int nAnnouncement) throws InterruptedException {
        _atomicRegister.setRid();
        int rid = _atomicRegister.getRid();
        _atomicRegister.clearAnswers();

        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new ReadRequest(_forums.get(i), _privateKey, _publicKey, publicKey,
                    _serverKey, nAnnouncement, rid, _clientStub, _atomicRegister)));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }

        return printAnnouncementsAtomic();
    }

    public String postGeneral(List<Thread> threads, String message, List<String> quotedAnnouncements) throws InterruptedException {
        _regularRegisterGeneral.setRid();
        int rid = _regularRegisterGeneral.getRid();
        _regularRegisterGeneral.clearAcklist();
        _regularRegisterGeneral.clearReadlist();

        // Before write, must read value to get most recent ts
        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new ReadGeneralRequest(_forums.get(i), _privateKey, _publicKey,
                    _serverKey, 1, rid, _regularRegisterGeneral)));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }

        int maxTs;
        try {
            maxTs = highestRes().getAnnouncements().get(0).getTs() + 1;
        } catch (IllegalArgumentException iae) {
            if(_regularRegisterGeneral.getReadlist().size() < 2) {
                maxTs = 1;
            } else {
                throw iae;
            }
        }

        threads = new ArrayList<>();
        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new PostGeneralRequest(_forums.get(i), _privateKey, _publicKey,
                    _serverKey, message, quotedAnnouncements, maxTs, _rank, rid, _regularRegisterGeneral)));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }

        System.out.println("\nVerifying post....");
        if (_regularRegisterGeneral.getAcklist().size() > (_N + _f) / 2) {
            _regularRegisterGeneral.clearAcklist();

            return WRITE_RESPONSE;
        } else {
            throw new IllegalArgumentException(BYZANTINE_ERROR);
        }
    }

    public String readGeneral(List<Thread> threads, int nAnnouncement) throws InterruptedException {
        _regularRegisterGeneral.setRid();
        int rid = _regularRegisterGeneral.getRid();
        _regularRegisterGeneral.clearAcklist();
        _regularRegisterGeneral.clearReadlist();

        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new ReadGeneralRequest(_forums.get(i), _privateKey, _publicKey,
                    _serverKey, nAnnouncement, rid, _regularRegisterGeneral)));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }

        return printAnnouncements();
    }

    private void readComplete() throws InterruptedException {
        _atomicRegister.clearAnswers();
        int rid = _atomicRegister.getRid();

        List<Thread> threads = new ArrayList<>();

        for (int i = 0; i < _N; i++) {
            threads.add(new Thread(new ReadCompleteRequest(_forums.get(i), _privateKey, _publicKey, _serverKey,
                    _clientStub, rid)));
            threads.get(i).start();
        }

        for (Thread t : threads) {
            t.join(20000);
            if (t.isAlive()) {
                t.interrupt();
            }
        }
    }

    @Override
    public void writeBack(Response res) {
        try {
            if(res.verify(_serverKey, 0, _atomicRegister.getRid())) {
                _atomicRegister.setAnswers(res);
            }
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
            System.out.println("Error. Insecure writeback.");
            return;
        }

        System.out.println("Wrote back " + res.getAnnouncements() + " announcements.");
    }

    private String printAnnouncements() {
        Response v = highestRes();
        List<Announcement> announcements = v.getAnnouncements();

        System.out.println();
        for (Announcement a : announcements) {
            System.out.println(a);
        }

        return "Got " + announcements.size() + " announcement(s)!";
    }

    private Response highestRes() throws IllegalArgumentException {
        List<Response> readlist = _regularRegisterGeneral.getReadlist();

        if (readlist.size() > (_N + _f) / 2) {

            int highestTs = -1;
            int highestRank = -1;
            Response highestResponse = null;

            for (Response res : readlist) {
                Announcement mostRecentAnnouncement = res.getAnnouncements().get(0);
                int ts = mostRecentAnnouncement.getTs();
                int rank = mostRecentAnnouncement.getRank();

                if (ts > highestTs || (ts == highestTs && rank >= highestRank)) {
                    highestTs = ts;
                    highestRank = rank;
                    highestResponse = res;
                }
            }

            _regularRegisterGeneral.clearReadlist();
            return highestResponse;
        }

        throw new IllegalArgumentException(BYZANTINE_ERROR);
    }

    private String printAnnouncementsAtomic() {
        try {
            Response v = bestQuorum();

            List<Announcement> announcements = v.getAnnouncements();

            System.out.println();
            for (Announcement a : announcements) {
                System.out.println(a);
            }

            readComplete();
            return "Got " + announcements.size() + " announcement(s)!";
        } catch (IllegalArgumentException | InterruptedException e) {
            throw new IllegalArgumentException(BYZANTINE_ERROR);
        }
    }

    private Response bestQuorum() {
        List<Response> answers = _atomicRegister.getAnswers();
        Response selected = null;

        for (Response answer : answers) {
            int quorumCounter = 0;
            List<Announcement> value = answer.getAnnouncements();
            int ts = answer.getAnnouncements().get(0).getTs();

            for (Response otherAnswer : answers) {
                if (otherAnswer.getAnnouncements().get(0).getTs() == ts && value.equals(otherAnswer.getAnnouncements())) {
                    quorumCounter++;
                }
            }

            if (quorumCounter > (_N + _f) / 2) {
                if (selected != null) {
                    if (selected.getAnnouncements().get(0).getTs() > answer.getAnnouncements().get(0).getTs()) {
                        selected = answer;
                    }
                }

                else {
                    selected = answer;
                }
            }
        }
        return selected;
    }

    private int requestInt(String prompt) throws NumberFormatException {
        int input;
        do {
            System.out.println(prompt);
            input = Integer.parseInt(_keyboardSc.nextLine());
        } while (input < 0);

        return input;
    }

    public static void main(String[] args) {
        Client c = new Client(args[0]);
        c.start();
    }
}
