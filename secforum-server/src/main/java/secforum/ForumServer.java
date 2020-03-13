package secforum;

import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ForumServer {
    public static void main(String[] args) {

        int registryPort = 1099;
        System.out.println("Main OK");

        try {
            Forum forum = new Forum();
            System.out.println("After create");

            Registry rmiregistry = LocateRegistry.createRegistry(registryPort);
            rmiregistry.rebind("forum", forum);

            System.out.println("Forum server ready");

            System.out.println("Awaiting connections");
            System.out.println("Press enter to shutdown");
            System.in.read();
            System.exit(0);

        } catch (IOException re) {
            re.printStackTrace();
        }
    }
}
