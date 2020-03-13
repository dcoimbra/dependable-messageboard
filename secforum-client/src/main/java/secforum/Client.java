package secforum;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

public class Client {
    ForumInterface forum;

    public Client() {
        try {
            forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Client c = new Client();
    }
}
