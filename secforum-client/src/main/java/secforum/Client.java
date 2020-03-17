package secforum;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
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
        int command;

        while (true) {
            System.out.println("1 - register\n2 - post\n3 - read\n4 - postGeneral\n5 - readGeneral");

            do {
                command = keyboardSc.nextInt();
            } while (command > 5 || command < 1);

            switch (command) {
                case 1:
                    System.out.println("Enter public key");
                    String username = keyboardSc.nextLine();
                    _forum.register(username);
                    break;
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
