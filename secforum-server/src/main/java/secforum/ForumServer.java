package secforum;

import java.io.*;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ForumServer {

    private static Forum _forum;
    private static String _filename = "src/main/resources/forum.ser";
    private static String _backup = "src/main/resources/forum_backup.ser";


    public ForumServer() throws RemoteException {

        try {
            ForumServer.readForum();
        } catch (FileNotFoundException e) {
            _forum = new Forum();
        }
    }

    public static Forum getForum() {
        return _forum;
    }

    public static void setForum(Forum forum) {
        _forum = forum;
    }

    public static void readForum() throws FileNotFoundException {
       try {
           FileInputStream file = new FileInputStream(_filename);
           ObjectInputStream in = new ObjectInputStream(file);

           Forum forum = (Forum) in.readObject();
           in.close();
           file.close();

           ForumServer.setForum(forum);
       } catch (ClassNotFoundException | IOException e) {
           try {
               FileInputStream file_backup = new FileInputStream(_backup);
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
        FileOutputStream file = new FileOutputStream(_filename);
        ObjectOutputStream out = new ObjectOutputStream(file);

        out.writeObject(forum);
        out.close();
        file.close();

        FileOutputStream backup = new FileOutputStream(_backup);
        ObjectOutputStream backup_out = new ObjectOutputStream(backup);

        backup_out.writeObject(forum);
        backup_out.close();
    }

    public static void main(String[] args) {

        int registryPort = 1099;
        System.out.println("Main OK");

        try {
            ForumServer server = new ForumServer();

            Registry rmiRegistry = LocateRegistry.createRegistry(registryPort);
            rmiRegistry.rebind("forum", ForumServer.getForum());

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
