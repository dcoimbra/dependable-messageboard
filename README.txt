Private key passwords for the 3 clients and the server:
Client 1: client1
Client 2: client2
Client 3: client3
Server 0: server0
Server 1: server1
Server 2: server2
Server 3: server3

How to run:
First, while on the root directory, install the interface module and run all tests:

mvn clean install

Then, navigate to the secforum-server module and start the server, providing its private key password as argument:

cd secforum-server/
mvn clean compile exec:java -Dexec.args="server"

After the server is up, you can now interact with it through the client interface.
Open 3 terminal windows, navigate to the secforum-client module and start a client in each one:

-----Terminal Window 1---------------------
cd secforum-client/
mvn clean compile exec:java -Dexec.args="1"
-------------------------------------------

-----Terminal Window 2---------------------
cd secforum-client/
mvn clean compile exec:java -Dexec.args="2"
-------------------------------------------

-----Terminal Window 3---------------------
cd secforum-client/
mvn clean compile exec:java -Dexec.args="3"
-------------------------------------------

IMPORTANT: For every request you make, you will be prompted for your private key password.

When invoking read or readGeneral, you must choose which client's board to read from by providing their ID: 1, 2, or 3.

KeyStore files for the clients' key pairs are located in secforum-client/src/main/java/resources
KeyStore file for the server's key pair is located in secforum-server/src/main/java/resources

Backup files for the server are located in secforum-server/src/main/java/resources

