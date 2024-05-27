Authentication components

Client Authenticator

Client Authenticator starts with the client and waits for a connection to the server
When connected it attemps a secure key exchange and shared key(shared secret) creation using the Diffie–Hellman Algorithm.<sup>(1)</sup>
After the shared key has been created it waits for the user to enter the login details
that will be encrypted with symmetric Aes 256-bit encryption with the shared key created before.
The Authentication is completed after the login details have been send has verified by the server.
An Authenticated Successfully msg is written in the unity log if successfull; failed otherwise.
An Authentication Completed msg is written to the console when its completed regardless of the result.


Server Authenticator

Server Authenticator starts with the server and waits for a client to connect.
Upon connection it starts the secure key exchange and shared key(shared secret) creation using the Diffie–Hellman Algorithm.
After the shared key has been created it waits for the client to send the login details
that will be authenticated. The server then verifies the login details against a database
or where the login have been stored. Then sends a broadcast(msg) to the server about the
authentication result and writes Authentication completed in the console when completed.

How to use:

Client Authenticator:

Put the Client Authenticator in a GameObject
Use the method AuthenticateClient along with either the serialized InputField's username and password
or some variables containing the username and password.
AuthenticateClient exspects the username and password to be string type that is then converted to a byte array,
encrypted and send to server with AuthenticationRequestBroadcast struct.

Server Authenticator

Put the Server Authenticator in the Fishnet NetworkManager game object
use the serialized username and passwrod to set the login details to be validated on server.
You can also implement your own system to read the username and password in from ex. a database
and use AcquireAndValidateLoginDetails(username,password) to pass login data read to server authenticator.
Make sure the Server Authenticator is properly set in the Authenticator field of Fishnet ServerManager component.

References:

1. How Diffie–Hellman works: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
