package secforum;

import java.io.*;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.ArrayList;
import java.util.List;

public class ForumServer {

    private static Forum _forum;
    private static final String _filename = "src/main/resources/forum";
    private static final String _backup = "src/main/resources/forum_backup";
    private static final String _extention = ".ser";
    private static int _id;

    public static Forum getForum() {
        return _forum;
    }

    public static void setForum(Forum forum) {
        _forum = forum;
    }

    public static void readForum() throws FileNotFoundException {
       try {
           FileInputStream file = new FileInputStream(_filename + _id + _extention);
           ObjectInputStream in = new ObjectInputStream(file);

           Forum forum = (Forum) in.readObject();
           in.close();
           file.close();

           ForumServer.setForum(forum);
       } catch (ClassNotFoundException | IOException e) {
           try {
               FileInputStream file_backup = new FileInputStream(_backup + _id + _extention);
               ObjectInputStream backup_in = new ObjectInputStream(file_backup);

               Forum forum = (Forum) backup_in.readObject();
               backup_in.close();
               file_backup.close();

               ForumServer.setForum(forum);
           } catch (FileNotFoundException fnfe) {
               throw fnfe;
           } catch (IOException | ClassNotFoundException ex) {
               ex.printStackTrace();
           }
       }
    }

    public static void writeForum(Forum forum) throws IOException {
        FileOutputStream file = new FileOutputStream(_filename + _id + _extention);
        ObjectOutputStream out = new ObjectOutputStream(file);

        out.writeObject(forum);
        out.close();
        file.close();

        FileOutputStream backup = new FileOutputStream(_backup + _id + _extention);
        ObjectOutputStream backup_out = new ObjectOutputStream(backup);

        backup_out.writeObject(forum);
        backup_out.close();
        backup.close();
    }

    public static List<ForumReliableBroadcastInterface> searchForums(int id) {
        List<ForumReliableBroadcastInterface> otherServers = new ArrayList<>();
        System.out.println("Looking for other servers...");
        boolean foundServer;

        for (int i = 0; i < 4; i++) {
            foundServer = false;
            while (!foundServer && i != id) {
                String name = "//localhost:" + (1099 + i) + "/forum" + i;
                try {
                    otherServers.add((ForumReliableBroadcastInterface) Naming.lookup(name));
                    System.out.println("Found server: " + name);
                    foundServer = true;
                } catch (MalformedURLException | RemoteException | NotBoundException ignored) {}
            }
        }

        return otherServers;
    }

    public static void main(String[] args) {
        String password = args[0];
        _id = Integer.parseInt(args[1]);
        int registryPort = 1099;
        System.out.println("Main OK");

        System.out.println("Id: " + _id);
        System.out.println("Port: " + (registryPort + _id));

        try {
            try {
                ForumServer.readForum();
            } catch (FileNotFoundException e) {
                _forum = new Forum(password, _id);
            }
            Registry rmiRegistry = LocateRegistry.createRegistry(registryPort + _id);
            rmiRegistry.rebind("forum" + _id, ForumServer.getForum());

            List<ForumReliableBroadcastInterface> otherServers = searchForums(_id);
            ForumServer.getForum().setOtherServers(otherServers);

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
