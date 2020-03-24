package secforum;

import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client {
    PublicKey _publicKey;
    ForumInterface _forum;
    Scanner keyboardSc;

    public Client(String id) {
        try {
            _publicKey = decodePublicKey(id);
            System.out.println(_publicKey);
            _forum = (ForumInterface) Naming.lookup("//localhost:1099/forum");
            System.out.println("Found server");
            System.out.println(_forum.hello("client"));
        } catch (RemoteException | NotBoundException | MalformedURLException e) {
            System.out.println(e.getMessage());
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        keyboardSc = new Scanner(System.in);
    }

    public void start() throws RemoteException {
        int command, nAnnouncement;
        String id, message;
        PublicKey publicKey;

        while (true) {
            System.out.println("1 - register\n2 - post\n3 - read\n4 - postGeneral\n5 - readGeneral\n6 - exit");

            try {

                command = Integer.parseInt(keyboardSc.nextLine());

                switch (command) {
                    case 1:
                        _forum.register(_publicKey);
                        break;

                    case 2:
                        if(_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter the message to be posted:");
                            message = keyboardSc.nextLine();

                            _forum.post(_publicKey, message, new ArrayList<>(), LocalDateTime.now());
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }

                        break;

                    case 3:
                        if(_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter client id:");
                            id = keyboardSc.nextLine();
                            publicKey = decodePublicKey(id);

                            System.out.println("Enter the number of announcements:");
                            nAnnouncement = Integer.parseInt(keyboardSc.nextLine());

                            List<Announcement> list = _forum.read(publicKey, nAnnouncement);

                            System.out.println("Got " + list.size() + " announcements!");
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }
                        break;

                    case 4:
                        if(_forum.verifyRegistered(_publicKey)) {
                            System.out.println("Enter the message to be posted:");
                            message = keyboardSc.nextLine();

                            _forum.postGeneral(_publicKey, message, new ArrayList<>(), LocalDateTime.now());
                        } else {
                            System.out.println("You need to register first in order to use the app");
                        }

                        break;

                    case 5:
                        if (_forum.verifyRegistered(_publicKey)) {
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
            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }
    }


    public static PublicKey decodePublicKey(String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        FileInputStream fis = new FileInputStream("src/main/resources/pub" + id + ".key");
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }


    public static void main(String[] args) {
        Client c = new Client(args[0]);

        try {
            c.start();
        } catch (RemoteException re) {
            System.out.println(re.getMessage());
        }
    }
}
