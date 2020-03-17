package secforum;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

public class Client {
    ForumInterface _forum;

    public Client() {
        try {
            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
        } catch (RemoteException | NotBoundException | MalformedURLException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        Client c = new Client();
    }
}
