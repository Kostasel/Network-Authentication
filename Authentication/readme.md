Authentication components

Client Authenticator

Client Authenticator starts with the client and waits for a connection to the server
When connected it attemps a secure key exchange and shared key(shared secret) creation using the Diffe-Hellman Algorithm.
After the shared key has been created it waits for the user to enter the login details
that will be encrypted with symmetric Aes 256-bit encryption with the shared key created before.
The Authentication is completed after the login details have been send has verified by the server.
An Authenticated Successfully msg is written in the unity log if successfull; failed otherwise.
An Authentication Completed msg is written to the console when its completed regardless of the result.


Server Authenticator

Server Authenticator starts with the server and waits for a client to connect.
Upon connection it starts the secure key exchange and shared key(shared secret) creation using the Diffe-Hellman Algorithm.
After the shared key has been created it waits for the client to send the login details
that will be authenticated. The server then verifies the login details against a database
or where the login have been stored. Then sends a broadcast(msg) to the server about the
authentication result and writes Authentication completed in the console when completed.
