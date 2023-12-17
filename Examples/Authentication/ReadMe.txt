Here you can find an example of how to create authentication with this solution.

Usage:
1. Launch the scene, start the server and the client.
2. Write your username and password into provided fields.
3. Click "Login" to launch the auth request.

All the data is encrypted prior to being transmitted with Aes 128 bit encryption.
Before the authentication is started the client and server are doing an asymetric 1024 bit
diffie-hellman-merkle key exchange and both agree on a shared key that will be used to encrypt the
authentication data that will be transmitted.

The LoginCanvas Prefab is fully functional and used in the Example Client authenticator scene.
It uses the legacy ui for compatibility reasons and shows how you can use ClientAuthenticator
component on a login screen.

See the console for useful information or errors.