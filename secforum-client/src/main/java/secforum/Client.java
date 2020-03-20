package secforum;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client {
    ForumInterface _forum;
    Scanner keyboardSc;

    public Client() {
        try {
            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
            System.out.println(_forum.hello("client"));
        } catch (RemoteException | NotBoundException | MalformedURLException e) {
            System.out.println(e.getMessage());
        }

        keyboardSc = new Scanner(System.in);
    }

    public void start() throws RemoteException {
        int command, nAnnouncement;
        String username = null, message;

        while (true) {
            System.out.println("1 - register\n2 - post\n3 - read\n4 - postGeneral\n5 - readGeneral\n6 - exit");

            try {

                command = Integer.parseInt(keyboardSc.nextLine());

                switch (command) {
                    case 1:
                        System.out.println("Enter public key:");
                        username = keyboardSc.nextLine();

                        _forum.register(username);
                        break;

                    case 2:
                        if(_forum.verifyRegistered(username)) {
                            System.out.println("Enter the message to be posted:");
                            message = keyboardSc.nextLine();

                            _forum.post(username, message, new ArrayList<>(), LocalDateTime.now());
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }

                        break;

                    case 3:
                        if(_forum.verifyRegistered(username)) {
                            System.out.println("Enter public key:");
                            username = keyboardSc.nextLine();

                            System.out.println("Enter the number of announcements:");
                            nAnnouncement = Integer.parseInt(keyboardSc.nextLine());

                            List<Announcement> list = _forum.read(username, nAnnouncement);

                            System.out.println("Got " + list.size() + " announcements!");
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }
                        break;

                    case 4:
                        if(_forum.verifyRegistered(username)) {
                            System.out.println("Enter public key:");
                            username = keyboardSc.nextLine();

                            System.out.println("Enter the message to be posted:");
                            message = keyboardSc.nextLine();

                            _forum.postGeneral(username, message, new ArrayList<>(), LocalDateTime.now());
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }

                        break;

                    case 5:
                        if(_forum.verifyRegistered(username)) {
                            System.out.println("Enter the number of announcements:");
                            nAnnouncement = Integer.parseInt(keyboardSc.nextLine());

                            List<Announcement> listGeneral = _forum.readGeneral(nAnnouncement);

                            System.out.println("Got " + listGeneral.size() + " announcements!");
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }
                        break;

                    case 6:
                        System.out.println("Thank you for using the app");
                        System.exit(0);


                    default:
                        System.out.println("ERROR. Must be between 1 and 6");
                        break;
                }
            } catch (NumberFormatException e) {
                System.out.println("ERROR. Must be number");
            } catch (RemoteException e) {
                System.out.println("ERROR. Server could not finish the operation. Try again");
            }
        }
    }

    public static void main(String[] args) {
        Client c = new Client();

        try {
            c.start();
        } catch (RemoteException re) {
            System.out.println(re.getMessage());
        }
    }
}
