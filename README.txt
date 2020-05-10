Private key passwords for the 3 clients and the server:
Client 1: client1
Client 2: client2
Client 3: client3
Server 0: server0
Server 1: server1
Server 2: server2
Server 3: server3

How to run:
First, while on the root directory, install the all the modules:

mvn clean install -DskipTests

Then start the 4 servers, providing their private key password and id as arguments.
Open 4 terminal windows, navigate to the secforum-server module and start a server in each one:

-----Terminal Window 1---------------------
cd secforum-server/
mvn clean compile exec:java -Dexec.args="server 0"
-------------------------------------------

-----Terminal Window 2---------------------
cd secforum-server/
mvn clean compile exec:java -Dexec.args="server 1"
-------------------------------------------

-----Terminal Window 3---------------------
cd secforum-server/
mvn clean compile exec:java -Dexec.args="server 2"
-------------------------------------------

-----Terminal Window 4---------------------
cd secforum-server/
mvn clean compile exec:java -Dexec.args="server 3"
-------------------------------------------

After the servers are up, you can now interact with them through the client interface.
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

IMPORTANT:
At the start of the execution, you will be prompted for your private key password.
When invoking read, you must choose which client's board to read from by providing their ID: 1, 2, or 3.

KeyStore files for the clients' key pairs are located in secforum-client/src/main/java/resources
KeyStore files for the servers' key pairs are located in secforum-server/src/main/java/resources

Backup files for the servers are located in secforum-server/src/main/java/resources

How to test:
Setup the servers in the same way as in "How to run"
Open a new terminal and in the root directory, run the following command:

mvn test

This will run all tests in each module.
Note that you need the servers running, because the client tests will interact with server.
Also note that you will need to close and then open the servers, in order to clean the boards from the test's operations.