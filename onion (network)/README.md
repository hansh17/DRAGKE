# 2018s-onion-team1

# Team member
- Jiwon Choi(Team leader)
- Seongho Han
- Mincheol son
- Dauren serkeshev

# Requirement 
- Two servers are required for Onion Messenger to work.

1. DB server: A server that provides a list of people who are currently connected to the network.

2. Public Key Server: A server that distributes users' public keys. Use Github's IndividualKeys page to get public key information.


# Onion Router
![Onion](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e1/Onion_diagram.svg/1200px-Onion_diagram.svg.png)  
[reference] https://en.wikipedia.org/wiki/Onion_routing
  
Onion is a data structure formed by "packing" a message into a continuous encryption layer.

The original message is encrypted with multiple layers and sent to the next node from the sender's node.

Encrypted data is decrypted each time through the node.

The contents of the original message can be known only when reaching the recipient's node.

No node in the circuit knows whether the previous node is the source of data or another intermediary node.



# Our Protocol 

All data is transmitted in file format. The detail of Protocol is described as below.

- In the case of File

| line No. | Description      |
|----------|------------------|
|  line 1  | "final" |
|  line 2  | "File"  |
|  line 3  |  [Sender name]  |
|  line 4  |   [File name]   |
|  line 5  | [Message Block] |


- In the case of Text

| line No. | Description      |
|----------|------------------|
|  line 1  | "final" |
|  line 2  | "File"  |
|  line 3  |  [Sender name]  |
|  line 4  |      NULL       |
|  line 5  | [Message Block] |



# Description of onion messenger
1. The user who enters the network registers [his IP, his Port, his GibhubID] in the DB server and notifies the connection to the DB server.
 
2. The user obtains a list of [IP, Port, GibhubID] of the users currently connected to the network from the DB server.

3. The user downloads the GibhubID.pub key from the Github server based on the user list obtained from the DB server and imports it.

4. Determine the Relay Point at random from user list.
   ex) When A sends a message to B, relay is randomly determined in the form A-D-E-C-B.

5. Encrypt file.txt appropriately for the route node.

	ex) When the route is A-D-E-C-B, the encryption proceeds sequentially 4 times according to the order of the nodes. 
	
	file1.txt = B's IP + B's Port + enc(file.txt,  B's public key)  
	
	file2.txt = C's IP + C's Port + enc(file1.txt, C's public key)  
	
	file3.txt = E's IP + E's Port + enc(file2.txt, E's public key)  
    
	file4.txt = D's IP + D's Port + enc(file3.txt, D's public key)  
	   
6. After encryption is completed, file4.txt is transferred as shown below and decrypted in order.

	A: Transfer file4.txt to Introduction Points (D).

	D: Decrypt file4.txt with D's private key to obtain file3.txt.

       Send file3.txt to E

    E: Decrypt file3.txt with E's private key to obtain file2.txt.
    
	   Send file2.txt to C
    
	C: Decrypt file2.txt with C's private key to get file1.txt.
    
	   Send file1.txt to B.
   
	B: Decrypt file1.txt with B's private key to get file.txt.


In the course of a series of transmissions, the anonymity of the sender and recipient is ensured and the encrypted file can be transmitted securely.

[https://gitpitch.com/KAIST-IS521/2018s-presentation-team1/onion](https://gitpitch.com/KAIST-IS521/2018s-presentation-team1/onion) (For details)

                  
# Work Distribution

| Name             | Role                     |
|------------------|--------------------------|
| Jiwon Choi       | DB Server & DB Client & manage whole project  |
| Seongho Han      | PGP encryption & protorol & make presentation |
| Mincheol son     | Manage PGP key & protorol & make demo video, onion slides |
| Dauren serkeshev | protocol, Create docker   & make onion slides |

